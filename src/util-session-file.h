#ifndef UTILSESSIONFILE_H
#define UTILSESSIONFILE_H

int update_session_file_start (packetinfo *pi, signature *sig);
int update_session_file_end (packetinfo *pi, signature *sig);
void print_session (packetinfo *pi, bstring filetype);

#endif // UTILSESSIONFILE_H
