#include "nftracker.h"
#include "util-session-file.h"
#include "util-log.h"
#include "config.h"

extern globalconfig config;

int update_session_file_start(packetinfo *pi, signature *sig)
{
    files *tmpfiles;
    tmpfiles = pi->cxt->files;

    while (tmpfiles != NULL) {
        if ( tmpfiles->sig == sig) {
            SET_FILE_START(tmpfiles);
            return 0;
        }
        tmpfiles = tmpfiles->next;
    }

    if (tmpfiles == NULL) {
        files *f = (files *)calloc(1, sizeof(files));
        if (f == NULL) {
            printf("Error allocating file entry\n");
            exit(EXIT_FAILURE);
        }
        f->prev = NULL;
        f->next = pi->cxt->files;
        f->sig = sig;
        SET_FILE_START(f);
        pi->cxt->files->prev = f;
        pi->cxt->files = f;
        return 0;
    }
}

int update_session_file_end(packetinfo *pi, signature *sig)
{
    files *tmpfiles;
    tmpfiles = pi->cxt->files;

    while (tmpfiles != NULL) {
        if ( tmpfiles->sig == sig) {
            SET_FILE_END(tmpfiles);
            if (ISSET_FILE_START(tmpfiles)) { // Should always be true here!
                print_session(pi, sig->filetype);
            }
            return 0;
        }
        tmpfiles = tmpfiles->next;
    }
    return 1;
}

void print_session(packetinfo *pi, bstring filetype)
{
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

    printf("%ld,%u,%s,%u,%s,%u,%s\n",pi->cxt->start_time,pi->cxt->proto,
        src_s,ntohs(pi->cxt->s_port),dst_s,ntohs(pi->cxt->d_port),(char *)bdata(filetype));
}

