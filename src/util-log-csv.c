#include "nftracker.h"
#include "util-log.h"
#include <stdio.h>
#include "bstrlib.h"
#include "util-log-csv.h"
#include "config.h"

extern globalconfig config;

void log_files_csv (packetinfo *pi, bstring filetype)
{
    FILE *nftFile;
    //char *nftfname;
    //nftfname = "/var/log/nftracker-csv.log";

    nftFile = fopen(config.logfile, "a");

    if (nftFile == NULL) {
        elog("[*] Cant open file %s\n",config.logfile);
        return;
    }

    static char src_s[INET6_ADDRSTRLEN];
    static char dst_s[INET6_ADDRSTRLEN];

    if (pi->af == AF_INET) {
        if (!inet_ntop(AF_INET, &pi->cxt->s_ip.s6_addr32[0], src_s, INET_ADDRSTRLEN + 1 ))
            perror("Something died in inet_ntop");
        if (!inet_ntop(AF_INET, &pi->cxt->d_ip.s6_addr32[0], dst_s, INET_ADDRSTRLEN + 1 ))
            perror("Something died in inet_ntop");
    } else if (pi->af == AF_INET6) {
        if (!inet_ntop(AF_INET6, &pi->cxt->s_ip, src_s, INET6_ADDRSTRLEN + 1 ))
            perror("Something died in inet_ntop");
        if (!inet_ntop(AF_INET6, &pi->cxt->d_ip, dst_s, INET6_ADDRSTRLEN + 1 ))
            perror("Something died in inet_ntop");
    }

    fprintf(nftFile,"%ld,%u,%s,%u,%s,%u,%s\n",pi->cxt->start_time,pi->cxt->proto,
        src_s,ntohs(pi->cxt->s_port),dst_s,ntohs(pi->cxt->d_port),(char *)bdata(filetype));

    fclose(nftFile);
}

