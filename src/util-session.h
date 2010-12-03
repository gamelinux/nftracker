/* 
 * Author: Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Created on January 16, 2010, 1:18 PM
 */

#ifndef _UTIL_CXT_H
#define _UTIL_CXT_H

#include "nftracker.h"


/* connection hash bucket -- the hash is basically an array of these buckets.
 * Each bucket contains a connection or list of connections. All these have
 * the same hashkey (the hash is a chained hash). */
typedef struct _cxtbucket {
    connection *cxt;
} cxtbucket;

cxtbucket *cxt_hash;


/* prototypes */
void bucket_keys_NULL();
inline void cxt_update (packetinfo *, uint32_t);
connection *connection_alloc(void);
void cxt_update_dst (connection *cxt, packetinfo *pi);
void cxt_update_src (connection *cxt, packetinfo *pi);
inline void cxt_new (connection *cxt, packetinfo *pi);
void free_queue();
void reverse_pi_cxt(packetinfo *pi);
inline void connection_tracking(packetinfo *pi);
inline uint32_t make_hash(packetinfo *pi);
#endif /* _UTIL_CXT_H */
