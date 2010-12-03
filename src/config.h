#ifndef CONFIG_H
#define CONFIG_H

#include "nftracker.h"

// int inpacket, gameover, intr_flag;
typedef struct _globalconfig {
    uint64_t    nftrackerid;            /* uniq id */
    time_t      tstamp;                 /* Global timestamp */
    nft_stats   nftstats;               /* nftracker stats */
    pcap_t              *handle;        /* Pointer to libpcap handle */
    struct pcap_stat    ps;             /* libpcap stats */
    struct bpf_program  cfilter;        /**/
    bpf_u_int32         net_mask;       /**/
    uint8_t     cflags;                 /* config flags */
    uint8_t     cof;                    /* Flags for other; icmp,udp,other,.... */
    uint8_t     setfilter;
    uint8_t     drop_privs_flag;
    uint8_t     daemon_flag;
    char        errbuf[PCAP_ERRBUF_SIZE];   /**/
    char        *bpff;                  /**/
    char        *user_filter;           /**/
    char        *net_ip_string;         /**/
    connection  *bucket[BUCKET_SIZE];   /* Pointer to list of ongoing connections */
    connection  *cxtbuffer;             /* Pointer to list of expired connections */
    bstring     sig_file_magic;         /* Filename containing magic header signatures*/
    bstring     nftlog;                 /* Filename of nft.log */
    bstring     pcap_file;              /* Filename to pcap too read */
    signature   *magic_file_sig;        /* Pointer to a list of magic file header signatures */
//    fmask       *network[MAX_NETS];     /* Struct for fmask */
    char        *dev;                   /* Device name to use for sniffing */
    char        *group_name;            /* Groupe to drop privileges too */
    char        *user_name;             /* User to drop privileges too */
    char        *chroot_dir;            /* Directory to chroot to */
    char        *pidfile;               /* pidfile */
    char        *pidpath;               /* Path to pidfile */
    char        *true_pid_name;         /* Pid name */
    char        *s_net;                 /* Nets to look for sessions with files in */
    int         nets;                   /* */
    struct fmask network[MAX_NETS];     /* */
} globalconfig;
#define ISSET_CONFIG_VERBOSE(config)  (config.cflags & 0x01)
#define ISSET_CONFIG_INPACKET(config) (config.cflags & 0x02)
#define ISSET_CONFIG_TERM(config)     (config.cflags & 0x04)
#define ISSET_CONFIG_INTR(config)     (config.cflags & 0x08)

#define SET_CONFIG_VERBOSE(config)    (config.cflags |= 0x01)
#define SET_CONFIG_INPACKET(config)   (config.cflags |= 0x02)
#define SET_CONFIG_TERM(config)       (config.cflags |= 0x04)
#define SET_CONFIG_INTR(config)       (config.cflags |= 0x08)

#define UNSET_CONFIG_VERBOSE(config)  (config.cflags &= ~0x01)
#define UNSET_CONFIG_INPACKET(config) (config.cflags &= ~0x02)
#define UNSET_CONFIG_TERM(config)     (config.cflags &= ~0x04)
#define UNSET_CONFIG_INTR(config)     (config.cflags &= ~0x08)


#endif                          // CONFIG_H
