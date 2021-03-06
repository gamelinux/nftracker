/*
** Copyright (C) 2010 Edward Fjellskål <edwardfjellskaal@gmail.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "nftracker.h"
#include "config.h"
#include "util-log.h"
#include "util-session-file.h"

extern globalconfig config;

int update_session_file_start (packetinfo *pi, signature *sig);
int update_session_file_end (packetinfo *pi, signature *sig);
int seen_session_file_start(packetinfo *pi, signature *sig);

void search_payload(packetinfo *pi)
{
    int rc;                     /* PCRE */
    int ovector[15];
    int tmplen;
    int retval = 0;
    signature *tmpsig;

    if (pi->plen <= 0) return; // if almost no payload - skip !?
    tmplen = pi->plen;

    tmpsig = config.sig_file;
    while (tmpsig != NULL) {
        if (seen_session_file_start(pi, tmpsig) == 1) { // Not seen start sig
            rc = pcre_exec(tmpsig->regex_start, tmpsig->study_start, pi->payload, tmplen,
                       0, 0, ovector, 15);
            if (rc >= 0) {
                dlog("[*] - Matched start sig: %s\n",(char *)bdata(tmpsig->filetype));
                update_session_file_start(pi, tmpsig);
                retval = 1;
            }
        }
        if (seen_session_file_start(pi, tmpsig) == 0 && seen_session_file_end(pi, tmpsig) == 1) { // Seen start sig and no end sig
            rc = pcre_exec(tmpsig->regex_stop, tmpsig->study_stop, pi->payload, tmplen,
                       0, 0, ovector, 15);
            if (rc >= 0) {
                dlog("[*] - Matched stop sig: %s\n",(char *)bdata(tmpsig->filetype));
                update_session_file_end(pi, tmpsig);
                retval = 1;
            }
        }
        //if (retval == 1) return;
        tmpsig = tmpsig->next;
    }
}

