#include "nftracker.h"
#include "config.h"
#include "util-filter.h"
#include "util-log.h"
#include "decode.h"
#include "decode-ipv6.h"

extern globalconfig config;

void parse_ip4 (packetinfo *pi);
void prepare_ip4 (packetinfo *pi);
void prepare_ip4ip (packetinfo *pi);

void parse_ip4 (packetinfo *pi)
{       
    switch (pi->ip4->ip_p) {
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
            prepare_ip4ip(pi);
            break;
        case IP_PROTO_IP6:
            prepare_ip4ip(pi);
            break;

        default:
        prepare_other(pi);
        if (!pi->our)
            break;
        parse_other(pi);
    }
    return;
}

void prepare_ip4 (packetinfo *pi)
{
    config.nftstats.ip4_recv++;
    pi->af = AF_INET;
    pi->ip4 = (ip4_header *) (pi->packet + pi->eth_hlen);
    pi->packet_bytes = (pi->ip4->ip_len - (IP_HL(pi->ip4) * 4));
    // can be removed if references are replaced by macro
    //pi->ip_src.s6_addr32[0] = PI_IP4SRC(pi);
    //pi->ip_dst.s6_addr32[0] = PI_IP4DST(pi);

    pi->our = filter_packet(pi->af, &PI_IP4SRC(pi));
    vlog(0x3, "Got %s IPv4 Packet...\n", (pi->our?"our":"foregin"));
    return;
}

void prepare_ip4ip (packetinfo *pi)
{       
    packetinfo pipi;
    memset(&pipi, 0, sizeof(packetinfo));
    config.nftstats.ip4ip_recv++;
    pipi.pheader = pi->pheader;
    pipi.packet = (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));
    pipi.end_ptr = pi->end_ptr;
    if (pi->ip4->ip_p == IP_PROTO_IP4) {
        prepare_ip4(&pipi);
        parse_ip4(&pipi);
        return;
    } else {
        prepare_ip6(&pipi);
        parse_ip6(&pipi);
        return;
    }
}

