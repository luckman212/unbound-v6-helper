"""
purpose:
    - provide a method to blackhole AAAA responses for specific domains
    - change TTL for AAAA responses to avoid downtime when V6 gateway goes offline

sources:
    http://www.fit.vutbr.cz/~vasicek/nic-vip/pythonmod/examples/index.html
    http://www.fit.vutbr.cz/~vasicek/nic-vip/pythonmod/examples/example0.html (Fundamentals)
    http://www.fit.vutbr.cz/~vasicek/nic-vip/pythonmod/examples/example3.html (Response modification)
    https://github.com/NLnetLabs/unbound/tree/master/pythonmod/examples
    https://github.com/NLnetLabs/unbound/blob/master/pythonmod/doc/modules/functions.rst
    https://github.com/NLnetLabs/unbound/blob/master/pythonmod/doc/modules/struct.rst
    https://gist.github.com/FiloSottile/e2cffde2bae1ea0c14eada229543aebd
    https://github.com/episource/unbound-modules/blob/master/README.md

record types:
    https://cloud.google.com/dns/docs/records-overview
"""

from os.path import exists
import subprocess

domains = [
    "api.bitwarden.com.",
    "identity.bitwarden.com.",
    "unifi.reliable.network.",
    "unifi.reliablenetwork.co.",
    "nas.reliable.network.",
    "esxi02.reliable.network.",
]

min_ttl = 10
v6gw = None
v6down = None
try:
    cmd = subprocess.run(
        [ "/usr/local/sbin/read_xml_tag.sh", "string", "gateways/defaultgw6" ],
        check=True,
        capture_output=True,
        text=True
    )
    v6gw = cmd.stdout.strip()
    assert (len(v6gw) > 0)
    v6down = ''.join([ '/tmp/.down.', v6gw ]) 
except:
    log_err("no-aaaa: could not determine default IPv6 gateway")
else:
    log_info("no-aaaa: v6down canary file: %s" % v6down)

def init(id, cfg):
    return True

def deinit(id):
    return True

def inform_super(id, qstate, superqstate, qdata):
    return True

def setTTL(qstate, ttl):
    if qstate.return_msg:
        qstate.return_msg.rep.ttl = ttl
        if (qstate.return_msg.rep):
            for i in range(0,qstate.return_msg.rep.rrset_count):
                d = qstate.return_msg.rep.rrsets[i].entry.data
                for j in range(0,d.count+d.rrsig_count):
                    d.rr_ttl[j] = ttl

def operate(id, event, qstate, qdata):
    """
    log_info("pythonmod: operate() id: %d, event:%s" % (id, strmodulevent(event)))
    log_info("Query: %s %s %s" % (qstate.qinfo.qname, qstate.qinfo.qname_list, qstate.qinfo.qname_str))
    log_info("Type: %s (%d)" % (qstate.qinfo.qtype_str, qstate.qinfo.qtype))
    log_info("Class: %s (%d)" % (qstate.qinfo.qclass_str, qstate.qinfo.qclass))
    """
    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):

        if qstate.qinfo.qtype == RR_TYPE_AAAA:
            
            if v6down and exists(v6down):
                msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_AAAA, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
                #msg.answer.append("%s %d IN AAAA ::" % (qstate.qinfo.qname_str, min_ttl))
                msg.answer.append("%s %d IN TXT %s" % (qstate.qinfo.qname_str, min_ttl, f'"IPv6 gateway ({v6gw}) is offline"'))
                if not msg.set_return_msg(qstate):
                    qstate.ext_state[id] = MODULE_ERROR
                    return True
                #qstate.no_cache_lookup = 1
                #qstate.no_cache_store = 1
                qstate.return_rcode = RCODE_NOERROR
                qstate.ext_state[id] = MODULE_FINISHED
                verbose(3, "no-aaaa: IPv6 gateway is down, filtering AAAA response for %s" % qstate.qinfo.qname_str)
                return True

            #log_info("checking to see if %s matches any blocked domains" % qstate.qinfo.qname_str)
            if (qstate.qinfo.qname_str in domains) or (qstate.qinfo.qname_str.endswith(tuple(['.' + d for d in domains]))):
                msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
                if not msg.set_return_msg(qstate):
                    qstate.ext_state[id] = MODULE_ERROR
                    return True
                qstate.return_msg.rep.security = 2
                qstate.return_rcode = RCODE_NOERROR
                qstate.ext_state[id] = MODULE_FINISHED
                verbose(2, "no-aaaa: filtering AAAA request for %s" % qstate.qinfo.qname_str)
                return True

        #log_info("passing non-AAAA request: %s" % qstate.qinfo.qname_str)
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_MODDONE:
        #log_info("pythonmod: iterator module done")

        try:
            assert qstate.return_msg is not None
        except Exception as e:
            verbose(2, 'MODDONE but qstate.return_msg==None, %s' % repr(e))
            qstate.ext_state[id] = MODULE_FINISHED
            return True

        if qstate.qinfo.qtype == RR_TYPE_AAAA:
            try:
                invalidateQueryInCache(qstate, qstate.return_msg.qinfo)
                verbose(3, 'invalidated cache: %s' % qstate.qinfo.qname_str)
            except Exception as e:
                log_err('invalidateQueryInCache(): %s' % repr(e))
            #modify TTL to avoid caching in case V6 goes down
            setTTL(qstate, min_ttl)
            qstate.no_cache_store = 0
            try:
                storeQueryInCache(qstate, qstate.return_msg.qinfo, qstate.return_msg.rep, 0)
                verbose(3, 'cached query: %s' % qstate.qinfo.qname_str)
            except Exception as e:
                log_err('storeQueryInCache(): %s' % repr(e))
            qstate.return_msg.rep.security = 2
            qstate.return_rcode = RCODE_NOERROR

        qstate.ext_state[id] = MODULE_FINISHED
        return True

    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True

log_info("pythonmod: script loaded")
log_info("no-aaaa: filtering AAAA responses from: %s" % domains)
