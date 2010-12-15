/*
** This file is a part of nftracker.
**
** Copyright (C) 2010, Edward Fjellskål <edward.fjellskaal@gmail.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

/*  I N C L U D E S  *********************************************************/
#include <malloc.h>
#include "common.h"
#include "nftracker.h"
#include "config.h"
#include "decode.h"
#include "decode-ipv4.h"
#include "decode-ipv6.h"
#include "util-search.h"
#include "util-system.h"
#include "util-system-end.h"
#include "util-log.h"
#include "util-session.h"
#include "util-session-queue.h"
#include "util-filter-network.h"

/*  G L O B A L E S  *** (or candidates for refactoring, as we say)***********/
globalconfig config;
connection *bucket[BUCKET_SIZE];
connection *cxtbuffer = NULL;
asset *passet[BUCKET_SIZE];
signature *sig_serv_tcp = NULL;

char src_s[INET6_ADDRSTRLEN], dst_s[INET6_ADDRSTRLEN];
uint64_t hash;

struct fmask network[MAX_NETS];

/*  I N T E R N A L   P R O T O T Y P E S  ***********************************/
static void usage();
void set_pkt_end_ptr (packetinfo *pi);
inline int filter_packet(const int af, void *ip);

/* F U N C T I O N S  ********************************************************/

void got_packet(u_char * useless, const struct pcap_pkthdr *pheader,
                const u_char * packet)
{
    config.nftstats.got_packets++;
    packetinfo pstruct = {0};
    packetinfo *pi = &pstruct;
    pi->our = 1;
    pi->packet = packet;
    pi->pheader = pheader;
    set_pkt_end_ptr (pi);
    config.tstamp = pi->pheader->ts.tv_sec;
    if (ISSET_CONFIG_INTR(config) != 0) {
        check_interrupt();
    }
    SET_CONFIG_INPACKET(config);
    prepare_eth(pi);
    check_vlan(pi);

    if (pi->eth_type == ETHERNET_TYPE_IP) {
        prepare_ip4(pi);
        parse_ip4(pi);
        goto packet_end;
    } else if (pi->eth_type == ETHERNET_TYPE_IPV6) {
        prepare_ip6(pi);
        parse_ip6(pi);
        goto packet_end;
    }
    config.nftstats.otherl_recv++;
    vlog(0x3, "[*] ETHERNET TYPE : %x\n",pi->eth_hdr->eth_ip_type);

packet_end:
#ifdef DEBUG
    if (!pi->our) vlog(0x3, "Not our network packet. Tracked, but not logged.\n");
#endif
    UNSET_CONFIG_INPACKET(config);
    return;
}

void set_pkt_end_ptr (packetinfo *pi)
{
    /* Paranoia! */
    if (pi->pheader->len <= SNAPLENGTH) {
        pi->end_ptr = (pi->packet + pi->pheader->len);
    } else {
        pi->end_ptr = (pi->packet + SNAPLENGTH);
    }
    return;
}

void cxt_init()
 {
    /* alloc hash memory */
    cxt_hash = calloc(CXT_DEFAULT_HASHSIZE, sizeof(cxtbucket));
    if (cxt_hash == NULL) {
        printf("calloc failed %s\n", strerror(errno));
        exit(1);
    }
    uint32_t i = 0;

    /* pre allocate conection trackers */
    for (i = 0; i < CXT_DEFAULT_PREALLOC; i++) {
        connection *cxt = connection_alloc();
        if (cxt == NULL) {
            printf("ERROR: connection_alloc failed: %s\n", strerror(errno));
            exit(1);
        }
        cxt_enqueue(&cxt_spare_q,cxt);
     }
}

static void usage()
{
    printf("USAGE:\n");
    printf(" $ nftracker [options]\n");
    printf("\n");
    printf(" OPTIONS:\n");
    printf("\n");
    printf(" -i <iface>      Network device <iface> (default: eth0).\n");
    printf(" -r <file>       Read pcap <file>.\n");
    printf(" -c <file>       Read config from <file>\n");
    printf(" -b <filter>     Apply Berkeley packet filter <filter>.\n");
    //printf(" -d            to logdir\n");
    printf(" -u <user>       Run as user <user>.\n");
    printf(" -g <group>      Run as group <group>.\n");
    printf(" -a <nets>       Specify home nets (eg: '192.168.0.0/25,10.0.0.0/255.0.0.0').\n");
    printf(" -D              Enables daemon mode.\n");
    printf(" -h              This help message.\n");
    printf(" -v              Verbose.\n");
    exit(0);
}

int preallocate_cxt (void)
{
    int i;
    for (i=0;i<BUCKET_SIZE;i++) {
        bucket[i] = (connection *)calloc(1, sizeof(connection));
        if(bucket[i] == NULL)
            return 0;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    memset(&config, 0, sizeof(globalconfig));
    int ch = 0;
    set_default_config_options();
    //bstring pconfile = bfromcstr(CONFDIR "nftracker.conf");
    config.logfile = "/var/log/nftracker-csv.log"; // Default logfile if not defined in cmdline

    cxtbuffer = NULL;
    config.nftrackerid = 0;
    config.nets = 1;
    UNSET_CONFIG_INPACKET(config);
    UNSET_CONFIG_TERM(config);
    UNSET_CONFIG_INTR(config);

    signal(SIGTERM, gameover);
    signal(SIGINT, gameover);
    signal(SIGQUIT, gameover);
    signal(SIGALRM, set_end_sessions);
    //signal(SIGALRM, game_over); // Use this to debug segfault when exiting :)

    while ((ch = getopt(argc, argv, "C:c:b:Dg:hi:p:r:P:u:va:l:")) != -1)
        switch (ch) {
        case 'a':
            config.s_net = strdup(optarg);
            break;
//        case 'c':
//            pconfile = bfromcstr(optarg);
//            break;
//        case 'C':
//            config.chroot_dir = strdup(optarg);
//            break;
        case 'i':
            config.dev = strdup(optarg);
            break;
        case 'r':
            config.pcap_file = blk2bstr(optarg, strlen(optarg));
            break;
        case 'b':
            config.bpff = strdup(optarg);
            break;
        case 'v':
            //config.verbose++;
            SET_CONFIG_VERBOSE(config);
            break;
        case 'l':
            config.logfile = strdup(optarg);
            break;
        case 'h':
            usage();
            break;
        case 'D':
            config.daemon_flag = 1;
            break;
        case 'u':
            config.user_name = strdup(optarg);
            config.drop_privs_flag = 1;
            break;
        case 'g':
            config.group_name = strdup(optarg);
            config.drop_privs_flag = 1;
            break;
        case 'p':
            config.pidfile = strdup(optarg);
            break;
        case 'P':
            config.pidpath = strdup(optarg);
            break;
        default:
            exit(1);
            break;
        }

    if (ISSET_CONFIG_VERBOSE(config)) {
        printf("%08x =? %08x, endianness: %s\n\n", 0xdeadbeef, ntohl(0xdeadbeef), (0xdead == ntohs(0xdead)?"big":"little") );
    }
                
    //parse_config_file(pconfile);
    //init_logging();
    //bdestroy (pconfile);

    parse_nets(config.s_net, config.network);

    printf("\n[*] Running nftracker %s\n", VERSION);
    printf("[*] Using %s\n", pcap_lib_version());
    printf("[*] Using PCRE version %s\n", pcre_version());

    //if (config.verbose) display_config();
    //display_config();

    // should be config file too
//load_servicefp_file(1, CONFDIR "tcp-service.sig");

    //init_services();
    init_sigs();

    if (config.pcap_file) {
        /* Read from PCAP file specified by '-r' switch. */
        printf("[*] Reading from file %s\n", bdata(config.pcap_file));
        if (!(config.handle = pcap_open_offline(bdata(config.pcap_file), config.errbuf))) {
            printf("[*] Unable to open %s.  (%s)", bdata(config.pcap_file), config.errbuf);
        } 

    } else {

        if (getuid()) {
            printf("[*] You must be root..\n");
            return (1);
        }
    
        /*
         * look up an available device if non specified
         */
        if (config.dev == 0x0)
            config.dev = pcap_lookupdev(config.errbuf);
        printf("[*] Device: %s\n", config.dev);
    
        if ((config.handle = pcap_open_live(config.dev, SNAPLENGTH, 1, 500, config.errbuf)) == NULL) {
            printf("[*] Error pcap_open_live: %s \n", config.errbuf);
            exit(1);
        } //else if ((pcap_compile(config.handle, &config.cfilter, config.bpff, 1, config.net_mask)) == -1) {
          //  printf("[*] Error pcap_compile user_filter: %s\n",
          //         pcap_geterr(config.handle));
          //  exit(1);
        //}
    
        /*
         * B0rk if we see an error...
         */
        if (strlen(config.errbuf) > 0) {
            elog("[*] Error errbuf: %s \n", config.errbuf);
            exit(1);
        }

//        if(config.chroot_dir){
//            olog("[*] Chrooting to dir '%s'..\n", config.chroot_dir);
//            if(set_chroot()){
//                elog("[!] failed to chroot\n");
//                exit(1);
//            }
//        }
    
        if (config.drop_privs_flag) {
            olog("[*] Dropping privs...\n");
            drop_privs();
        }

        if (config.daemon_flag) {
            if (!is_valid_path(config.pidpath))
                elog
                    ("[*] PID path \"%s\" is bad, check privilege.", config.pidpath);
            openlog("nftracker", LOG_PID | LOG_CONS, LOG_DAEMON);
            olog("[*] Daemonizing...\n\n");
            daemonize(NULL);
        }
    
    }
 
    bucket_keys_NULL();
    alarm(CHECK_TIMEOUT);

    if ((pcap_compile(config.handle, &config.cfilter, config.bpff, 1, config.net_mask)) == -1) {
            printf("[*] Error pcap_compile user_filter: %s\n", pcap_geterr(config.handle));
            exit(1);
    }

    if (pcap_setfilter(config.handle, &config.cfilter)) {
            printf("[*] Unable to set pcap filter!  %s", pcap_geterr(config.handle));
    }

    cxt_init();
    printf("[*] Sniffing...\n\n");
    pcap_loop(config.handle, -1, got_packet, NULL);

    gameover();
    return (0);
}

