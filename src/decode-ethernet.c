#include "nftracker.h"
#include "config.h"

extern globalconfig config;

void prepare_eth (packetinfo *pi);

void prepare_eth (packetinfo *pi)
{
    if (pi->packet + ETHERNET_HEADER_LEN > pi->end_ptr) return;
    config.nftstats.eth_recv++;
    pi->eth_hdr  = (ether_header *) (pi->packet);
    pi->eth_type = ntohs(pi->eth_hdr->eth_ip_type);
    pi->eth_hlen = ETHERNET_HEADER_LEN;
    return;
}

