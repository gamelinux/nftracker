#include "nftracker.h"
#include "config.h"
#include "util-log.h"

extern globalconfig config;


inline int filter_packet(const int af, void *ip);

/* does this ip belong to our network? do we care about the packet?
 *
 * unfortunately pcap sends us packets in host order
 * Return value: boolean
 */
inline int filter_packet(const int af, void *ipptr)
//const struct in6_addr *ip_s)
{
    ip6v ip_vec;
    ip6v t;

    int i, our = 0;
    char output[MAX_NETS];
    switch (af) {
        case AF_INET:
        {
            uint32_t *ip = (uint32_t *) ipptr;
            for (i = 0; i < MAX_NETS && i < config.nets; i++) {
                if (config.network[i].type != AF_INET)
                    continue;
#if DEBUG == 2
                inet_ntop(af, &config.network[i].addr.s6_addr32[0], output, MAX_NETS);
                vlog(0x2, "Filter: %s\n", output);
                inet_ntop(af, &config.network[i].mask.s6_addr32[0], output, MAX_NETS);
                vlog(0x2, "mask: %s\n", output);
                inet_ntop(af, ip, output, MAX_NETS);
                vlog(0x2, "ip: %s\n", output);
#endif
                if((*ip & config.network[i].mask.s6_addr32[0])
                    == config.network[i].addr.s6_addr32[0]) {
                    our = 1;
                    break;
                }
            }
        }
        break;
        case AF_INET6:
        {
            /* 32-bit comparison of ipv6 nets.
             * can do better here by using 64-bit or SIMD instructions
             *
             *
             * PS: use same code for ipv4 - 0 bytes and SIMD doesnt care*/

            ip_vec.ip6 = *((struct in6_addr *)ipptr);
            for (i = 0; i < MAX_NETS && i < config.nets; i++) {
                if(config.network[i].type != AF_INET6)
                    continue;
#if DEBUG == 2
                inet_ntop(af, &config.network[i].addr, output, MAX_NETS);
                dlog("net:  %s\n", output);
                inet_ntop(af, &config.network[i].mask, output, MAX_NETS);
                dlog("mask: %s\n", output);
                inet_ntop(af, &PI_IP6SRC(pi), output, MAX_NETS);
                dlog("ip: %s\n", output);
#endif
                if (config.network[i].type == AF_INET6) {
#if(1)
                /* apologies for the uglyness */
#ifdef HAVE_SSE2
#define compare128(x,y) __builtin_ia32_pcmpeqd128((x), (y))
                    // the builtin is only available on sse2! 
                    t.v = __builtin_ia32_pcmpeqd128(
                      ip_vec.v & config.network[i].mask_v,
                      config.network[i].addr_v);
                    if (t.i[0] & t.i[1])
#else
#define compare128(x,y) memcmp(&(x),&(y),16)
                    t.v = ip_vec.v & config.network[i].mask_v;
                    // xor(a,b) == 0 iff a==b
                    if (!( (t.i[0] ^ config.network[i].addr64[0]) & 
                           (t.i[1] ^ config.network[i].addr64[1]) ))
#endif
                    {
                        our = 1;
                        break;
                    }

#else
                    if ((ip_s.s6_addr32[0] & config.network[i]->mask.s6_addr32[0])
                        == config.network[i]->addr.s6_addr32[0]
                        && (ip_s.s6_addr32[1] & config.network[i]->mask.s6_addr32[1])
                        == config.network[i]->addr.s6_addr32[1]
                        && (ip_s.s6_addr32[2] & config.network[i]->mask.s6_addr32[2])
                        == config.network[i]->addr.s6_addr32[2]
                        && (ip_s.s6_addr32[3] & config.network[i]->mask.s6_addr32[3])
                        == config.network[i]->addr.s6_addr32[3]) {
                        our = 1;
                        break;
                    }
#endif
                }
            }
        }
        break;
        default:
        fprintf(stderr,
            "non-ip packets of type %d aren't filtered by netmask yet\n", af);
            our = 1;
    }
#ifdef DEBUG
    if (af == AF_INET6){
        inet_ntop(af, (struct in6addr*) ipptr, output, MAX_NETS);
    }else{
        inet_ntop(af, (uint32_t*)ipptr, output, MAX_NETS);
    }
    if (our){
        vlog(0x2, "Address %s is in our network.\n", output);
    } else {
        vlog(0x2, "Address %s is not our network.\n", output);
    }
#endif
    return our;
}
