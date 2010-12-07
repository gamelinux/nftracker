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
        signature *tmpsig = tmpfiles->sig;
        if ( tmpsig == sig) {
            SET_FILE_START(tmpfiles);
            return 0;
        }
        tmpfiles = tmpfiles->next;
    }

    if (tmpfiles == NULL) {
        files *newfile = (files *)calloc(1, sizeof(files));
        if (newfile == NULL) {
            printf("Error allocating file entry\n");
            exit(EXIT_FAILURE);
        }
        newfile->prev = NULL;
        newfile->next = pi->cxt->files;
        newfile->sig = sig;
        SET_FILE_START(newfile);
        if (pi->cxt->files != NULL) pi->cxt->files->prev = newfile;
        pi->cxt->files = newfile;
        return 0;
    }
    return 1;
}

int seen_session_file_start(packetinfo *pi, signature *sig)
{
   files *tmpfiles;
    tmpfiles = pi->cxt->files;

    while (tmpfiles != NULL) {
        if ( tmpfiles->sig == sig) {
            if (ISSET_FILE_START(tmpfiles)) {
                return 0;
            }
        }
        tmpfiles = tmpfiles->next;
    }
    return 1;
}

int update_session_file_end(packetinfo *pi, signature *sig)
{
    files *tmpfiles;
    tmpfiles = pi->cxt->files;

    while (tmpfiles != NULL) {
        if ( tmpfiles->sig == sig) {
            if (ISSET_FILE_START(tmpfiles)) { // Should always be true here!
                print_session(pi, sig->filetype);
                UNSET_FILE_START(tmpfiles); // More files of same kind can pass
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

