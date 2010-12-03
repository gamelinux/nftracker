#include "nftracker.h"
#include "config.h"
#include "util-log.h"
#include "util-filter-network.h"

extern globalconfig config;

int parse_network (char *net_s, struct in6_addr *network)
{
    int type;
    char *t;
    if (NULL != (t = strchr(net_s, ':'))) {
        type = AF_INET6;
        if (!inet_pton(type, net_s, network)) {
            perror("parse_nets6");
            return -1;
        }
        printf("Network6 %-36s \t -> %08x:%08x:%08x:%08x\n",
               net_s,
               network->s6_addr32[0],
               network->s6_addr32[1],
               network->s6_addr32[2],
               network->s6_addr32[3]
              );
    } else {
        type = AF_INET;
        if (!inet_pton(type, net_s, &network->s6_addr32[0])) {
            perror("parse_nets");
            return -1;
        }
        printf("Network4 %16s \t-> 0x%08x\n", net_s, network->s6_addr32[0]);
    }
    return type;
}

int parse_netmask (char *f, int type, struct in6_addr *netmask)
{
    char *t;
    uint32_t mask;
    char output[MAX_NETS];
    // parse netmask into host order
    if (type == AF_INET && (t = strchr(f, '.')) > f && t-f < 4) {
        // full ipv4 netmask : dotted quads
        inet_pton(type, f, &netmask->s6_addr32[0]);
        printf("mask 4 %s \t-> 0x%08x\n", f, netmask->s6_addr32[0]);
    } else if (type == AF_INET6 && NULL != (t = strchr(f, ':'))) {
        // full ipv6 netmasĸ
        printf("mask 6 %s\n", f);
        inet_pton(type, f, netmask);
    } else {
        // cidr form
        sscanf(f, "%u", &mask);
        printf("cidr  %u \t-> ", mask);
        if (type == AF_INET) {
            uint32_t shift = 32 - mask;
            if (mask)
                netmask->s6_addr32[0] = ntohl( ((unsigned int)-1 >> shift)<< shift);
            else
                netmask->s6_addr32[0] = 0;

            printf("0x%08x\n", netmask->s6_addr32[0]);
        } else if (type == AF_INET6) {
            //mask = 128 - mask;
            int j = 0;
            memset(netmask, 0, sizeof(struct in6_addr));

            while (mask > 8) {
                netmask->s6_addr[j++] = 0xff;
                mask -= 8;
            }
            if (mask > 0) {
                netmask->s6_addr[j] = -1 << (8 - mask);
            }
            inet_ntop(type, &netmask->s6_addr32[0], output, MAX_NETS);
            printf("mask: %s\n", output);
            // pcap packets are in host order.
            netmask->s6_addr32[0] = ntohl(netmask->s6_addr32[0]);
            netmask->s6_addr32[1] = ntohl(netmask->s6_addr32[1]);
            netmask->s6_addr32[2] = ntohl(netmask->s6_addr32[2]);
            netmask->s6_addr32[3] = ntohl(netmask->s6_addr32[3]);

        }
    }
    return 0;
}

/* parse strings of the form ip/cidr or ip/mask like:
 * "10.10.10.10/255.255.255.128,10.10.10.10/25" and 
 * "dead:be:eef2:1aa::b5ff:fe96:37a2/64,..."
 *
 * an IPv6 address is 8 x 4 hex digits. missing digits are padded with zeroes.
 */
void parse_nets(const char *s_net, struct fmask *network)
{
    /* f -> for processing
     * p -> frob pointer
     * t -> to pointer */
    char *f, *p, *snet;
    int type, len, i = 0;
    struct in6_addr network6, netmask6;

    // snet is a mutable copy of the args,freed @ nets_end
    len = strlen(s_net);
    //snet = calloc(1, len);
    snet = calloc(1, (len + 1)); /* to have \0 too :-) */
    strncpy(snet, s_net, len);
    f = snet;
    while (f && 0 != (p = strchr(f, '/'))) {
        // convert network address
        *p = '\0';
        type = parse_network(f, &network6);
        if (type != AF_INET && type != AF_INET6) {
            perror("parse_network");
            goto nets_end;
        }
        // convert netmask
        f = p + 1;
        p = strchr(f, ',');
        if (p) {
            *p = '\0';
        }
        parse_netmask(f, type, &netmask6);

        // poke in the gathered information
        switch (type) {
            case AF_INET:
            case AF_INET6:
                network[i].addr = network6;
                network[i].mask = netmask6;
                network[i].type = type;
                break;

            default:
                fprintf(stderr, "parse_nets: invalid address family!\n");
                goto nets_end;
        }

        config.nets = ++i;

        if (i > MAX_NETS) {
            elog("Max networks reached, stopped parsing at %d nets.\n", i-1);
            goto nets_end;
        }


        // continue parsing at p, which might point to another network range
        f = p;
        if(p) f++;
    }
nets_end:
    free(snet);
    return;
}
