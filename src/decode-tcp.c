#include "nftracker.h"
#include "config.h"
#include "util-log.h"
#include "util-session.h"
#include "util-search-payload.h"
#include "decode-tcp.h"

extern globalconfig config;

void prepare_tcp (packetinfo *pi)
{
    config.nftstats.tcp_recv++;
    if (pi->af==AF_INET) {
        vlog(0x3, "[*] IPv4 PROTOCOL TYPE TCP:\n");
        pi->tcph = (tcp_header *) (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));
        pi->plen = (pi->pheader->caplen - (TCP_OFFSET(pi->tcph)) * 4 - (IP_HL(pi->ip4) * 4) - pi->eth_hlen);
        pi->payload = (char *)(pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4) + (TCP_OFFSET(pi->tcph) * 4));
    } else if (pi->af==AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE TCP:\n");
        pi->tcph = (tcp_header *) (pi->packet + pi->eth_hlen + IP6_HEADER_LEN);
        pi->plen = (pi->pheader->caplen - (TCP_OFFSET(pi->tcph)) * 4 - IP6_HEADER_LEN - pi->eth_hlen);
        pi->payload = (char *)(pi->packet + pi->eth_hlen + IP6_HEADER_LEN + (TCP_OFFSET(pi->tcph)*4));
    }
    pi->proto  = IP_PROTO_TCP;
    pi->s_port = pi->tcph->src_port;
    pi->d_port = pi->tcph->dst_port;
    connection_tracking(pi);
    //cx_track_simd_ipv4(pi);
    return;
}

void parse_tcp (packetinfo *pi)
{
    //update_asset(pi);
    vlog(0x3, "[*] - Got TCP package...\n");
    //printf("[*] - Got TCP package...\n");
    search_payload(pi);


    if (TCP_ISFLAGSET(pi->tcph, (TF_SYN))) {
        if (!TCP_ISFLAGSET(pi->tcph, (TF_ACK))) {
            return;
//        } else {
//            if (IS_COSET(&config,CO_SYNACK)) {
//                if (pi->sc != SC_SERVER) reverse_pi_cxt(pi);
//                return;
//            }
        }
    }

    if (pi->sc == SC_CLIENT && !ISSET_CXT_DONT_CHECK_CLIENT(pi)) {
        if (IS_CSSET(&config,CS_TCP_CLIENT)
                && !ISSET_DONT_CHECK_CLIENT(pi)) {
//            if (pi->af == AF_INET) client_tcp4(pi);
//                else client_tcp6(pi);
        }
//        goto bastard_checks;

    } else if (pi->sc == SC_SERVER && !ISSET_CXT_DONT_CHECK_SERVER(pi)) {
        if (IS_CSSET(&config,CS_TCP_SERVER)
                && !ISSET_DONT_CHECK_SERVICE(pi)) {
//            if (pi->af == AF_INET) service_tcp4(pi);
//                else service_tcp6(pi);
        }
//        goto bastard_checks;
    }
    vlog(0x3, "[*] - NOT CHECKING TCP PACKAGE\n");
    return;

//bastard_checks:
//    if (IS_COSET(&config,CO_ACK)
//            && TCP_ISFLAGSET(pi->tcph, (TF_ACK))
//            && !TCP_ISFLAGSET(pi->tcph, (TF_SYN))
//            && !TCP_ISFLAGSET(pi->tcph, (TF_RST))
//            && !TCP_ISFLAGSET(pi->tcph, (TF_FIN))) {
//        vlog(0x3, "[*] Got a STRAY-ACK: src_port:%d\n",ntohs(pi->tcph->src_port));
//        fp_tcp(pi, CO_ACK);
//        return;
//    } else if (IS_COSET(&config,CO_FIN) && TCP_ISFLAGSET(pi->tcph, (TF_FIN))) {
//        vlog(0x3, "[*] Got a FIN: src_port:%d\n",ntohs(pi->tcph->src_port));
//        fp_tcp(pi, CO_FIN);
//        return;
//    } else if (IS_COSET(&config,CO_RST) && TCP_ISFLAGSET(pi->tcph, (TF_RST))) {
//        vlog(0x3, "[*] Got a RST: src_port:%d\n",ntohs(pi->tcph->src_port));
//        fp_tcp(pi, CO_RST);
//        return;
//    }
}

