#include "nftracker.h"
#include "config.h"
#include "util-log.h"
#include "util-session.h"
#include "decode-others.h"
extern globalconfig config;

void prepare_other (packetinfo *pi)
{
    config.nftstats.othert_recv++;
    if (pi->af==AF_INET) {
        vlog(0x3, "[*] IPv4 PROTOCOL TYPE OTHER: %d\n",pi->ip4->ip_p);

    } else if (pi->af==AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE OTHER: %d\n",pi->ip6->next);

    }
    pi->s_port = 0;
    pi->d_port = 0;
    connection_tracking(pi);
    return;
}

void parse_other (packetinfo *pi)
{
//    update_asset(pi);

//    if (pi->cxt->check == 0x00) {
//        if (IS_COSET(&config,CO_OTHER)) {
//            pi->cxt->check = 0x01; // no more checks
//            // service_other(*pi->ip4,*transporth);
//            // fp_other(pi->ipX, ttl, ipopts, len, id, ipflags, df);
//        } else {
//            vlog(0x3, "[*] - NOT CHECKING *OTHER* PACKAGE\n");
//        }
//    }
}

