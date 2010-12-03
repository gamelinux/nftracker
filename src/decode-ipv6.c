#include "nftracker.h"
#include "config.h"
#include "util-log.h"
#include "util-filter.h"
#include "decode.h"
#include "decode-ipv4.h"

extern globalconfig config;

void parse_ip6 (packetinfo *pi);
void prepare_ip6ip (packetinfo *pi);
void prepare_ip6 (packetinfo *pi);

void parse_ip6 (packetinfo *pi)
{
    switch (pi->ip6->next) {
        case IP_PROTO_TCP:
            prepare_tcp(pi);
            if (!pi->our)
                break;
            parse_tcp(pi);
            break;
        case IP_PROTO_UDP:
            prepare_udp(pi);
            if (!pi->our)
                break;
            parse_udp(pi);
            break;
        case IP_PROTO_IP4:
            prepare_ip6ip(pi);
            break;
        case IP_PROTO_IP6:
            prepare_ip6ip(pi);
            break;

        default:
        prepare_other(pi);
        break;
    }
    return;
}

void prepare_ip6ip (packetinfo *pi)
{               
    packetinfo pipi;
    memset(&pipi, 0, sizeof(packetinfo));
    config.nftstats.ip6ip_recv++;
    pipi.pheader = pi->pheader;
    pipi.packet = (pi->packet + pi->eth_hlen + IP6_HEADER_LEN);
    pipi.end_ptr = pi->end_ptr;
    if (pi->ip6->next == IP_PROTO_IP4) {
        prepare_ip4(&pipi);
        parse_ip4(&pipi);
        return; 
    } else {
        prepare_ip6(&pipi);
        parse_ip6(&pipi);
        return;
    }       
}             

void prepare_ip6 (packetinfo *pi)
{
    config.nftstats.ip6_recv++;
    pi->af = AF_INET6;
    pi->ip6 = (ip6_header *) (pi->packet + pi->eth_hlen);
    pi->packet_bytes = pi->ip6->len;
    // may be dropped due to macros plus
    //pi->ip_src = PI_IP6SRC(pi);
    //pi->ip_dst = PI_IP6DST(pi);
    pi->our = filter_packet(pi->af, &PI_IP6SRC(pi));
    vlog(0x3, "Got %s IPv6 Packet...\n", (pi->our?"our":"foregin"));
    return;
}

