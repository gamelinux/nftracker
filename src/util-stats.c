#include "config.h"
#include "util-stats.h"

/*  G L O B A L E S  *********************************************************/
extern globalconfig config;

void print_pcap_stats()
{
    if (config.handle == NULL) return;
    if (pcap_stats(config.handle, &config.ps) == -1) {
        pcap_perror(config.handle, "pcap_stats");
    }
    printf("\n-- libpcap:");
    printf("\n-- Total packets received                 :%12u",config.ps.ps_recv);
    printf("\n-- Total packets dropped                  :%12u",config.ps.ps_drop);
    printf("\n-- Total packets dropped by Interface     :%12u",config.ps.ps_ifdrop);
}

void print_stats()
{
    printf("\n-- nftracker:");
    printf("\n-- Total packets received from libpcap    :%12u",config.nftstats.got_packets);
    printf("\n-- Total Ethernet packets received        :%12u",config.nftstats.eth_recv);
    printf("\n-- Total VLAN packets received            :%12u",config.nftstats.vlan_recv);
//    printf("\n-- Total ARP packets received             :%12u",config.nftstats.arp_recv);
    printf("\n-- Total IPv4 packets received            :%12u",config.nftstats.ip4_recv);
    printf("\n-- Total IPv6 packets received            :%12u",config.nftstats.ip6_recv);
//    printf("\n-- Total Other link packets received      :%12u",config.nftstats.otherl_recv);
//    printf("\n-- Total IPinIPv4 packets received        :%12u",config.nftstats.ip4ip_recv);
//    printf("\n-- Total IPinIPv6 packets received        :%12u",config.nftstats.ip6ip_recv);
//    printf("\n-- Total GRE packets received             :%12u",config.nftstats.gre_recv);
    printf("\n-- Total TCP packets received             :%12u",config.nftstats.tcp_recv);
    printf("\n-- Total UDP packets received             :%12u",config.nftstats.udp_recv);
//    printf("\n-- Total ICMP packets received            :%12u",config.nftstats.icmp_recv);
    printf("\n-- Total Other transport packets received :%12u",config.nftstats.othert_recv);
    printf("\n--");
    printf("\n-- Total sessions tracked                 :%12lu",config.nftrackerid);
//    printf("\n-- Total files detected                   :%12u",config.nftstats.files);
//    printf("\n-- Total EXE files detected               :%12u",config.nftstats.exe);
//    printf("\n-- Total PDF files detected               :%12u",config.nftstats.pdf);
//    printf("\n-- Total PE  files detected               :%12u",config.nftstats.pe);
//    printf("\n-- Total DOC files detected               :%12u",config.nftstats.doc);
}

