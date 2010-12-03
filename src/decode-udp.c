#include "nftracker.h"
#include "config.h"
#include "util-log.h"
#include "util-session.h"
#include "decode-udp.h"

extern globalconfig config;

void prepare_udp (packetinfo *pi)
{
    config.nftstats.udp_recv++;
    if (pi->af==AF_INET) {
        vlog(0x3, "[*] IPv4 PROTOCOL TYPE UDP:\n");
        pi->udph = (udp_header *) (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));
        pi->plen = pi->pheader->caplen - UDP_HEADER_LEN -
                    (IP_HL(pi->ip4) * 4) - pi->eth_hlen;
        pi->payload = (char *)(pi->packet + pi->eth_hlen +
                        (IP_HL(pi->ip4) * 4) + UDP_HEADER_LEN);

    } else if (pi->af==AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE UDP:\n");
        pi->udph = (udp_header *) (pi->packet + pi->eth_hlen + + IP6_HEADER_LEN);
        pi->plen = pi->pheader->caplen - UDP_HEADER_LEN -
                    IP6_HEADER_LEN - pi->eth_hlen;
        pi->payload = (char *)(pi->packet + pi->eth_hlen +
                        IP6_HEADER_LEN + UDP_HEADER_LEN);
    }
    pi->proto  = IP_PROTO_UDP;
    pi->s_port = pi->udph->src_port;
    pi->d_port = pi->udph->dst_port;
    connection_tracking(pi);
    return;
}

void parse_udp (packetinfo *pi)
{
    //update_asset(pi);
    udp_guess_direction(pi); // fix DNS server transfers?

    if (IS_CSSET(&config,CS_UDP_SERVICES)) {
        if (pi->af == AF_INET) {

            if (!ISSET_DONT_CHECK_SERVICE(pi)||!ISSET_DONT_CHECK_CLIENT(pi)) {
                //service_udp4(pi);
            }
            //if (IS_COSET(&config,CO_UDP)) fp_udp4(pi, pi->ip4, pi->udph, pi->end_ptr);
        } else if (pi->af == AF_INET6) {
            if (!ISSET_DONT_CHECK_SERVICE(pi)||!ISSET_DONT_CHECK_CLIENT(pi)) {
                //service_udp6(pi);
            }
            /* fp_udp(ip6, ttl, ipopts, len, id, ipflags, df); */
        }
        return;
    } else {
        vlog(0x3, "[*] - NOT CHECKING UDP PACKAGE\n");
        return;
    }
}

void udp_guess_direction(packetinfo *pi)
{
    /* Stupid hack :( for DNS/port 53 */
    if (ntohs(pi->d_port) == 53) {
        if (pi->sc == SC_CLIENT) return;
            else pi->sc = SC_CLIENT;

    } else if (ntohs(pi->s_port) == 53) {
        if (pi->sc == SC_SERVER) return;
            else pi->sc = SC_SERVER;
    }
}


