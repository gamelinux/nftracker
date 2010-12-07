#ifndef UTILSESSIONFILE_H
#define UTILSESSIONFILE_H

#ifndef NFTRACKER_H
#include "nftracker.h"
#endif

typedef struct _files {
    struct  _files    *prev;     /* prev files structure */
    struct  _files    *next;     /* next files structure */
    struct  signature *sig;      /* pointer to sig that matched */
    uint8_t seen;                /* seen start/stop for sig */
} files;
#define SET_FILE_START(files)   (files.seen |= 0x01)
#define SET_FILE_END(files)     (files.seen |= 0x02)
#define ISSET_FILE_START(files) (files.seen &  0x01)
#define ISSET_FILE_END(fileS)   (files.seen &  0x02)

#endif // UTILSESSIONFILE_H
