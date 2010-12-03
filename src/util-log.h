#define elog(fmt, ...) fprintf(stderr, ("[%s:%d(%s)] " fmt), __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__);
#define olog(fmt, ...) do{ fprintf(stdout, (fmt), ##__VA_ARGS__); }while(0)
#ifdef DEBUG
#define dlog(fmt, ...) do { fprintf(stderr, ("[%s:%d(%s)] " fmt), __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__);} while(0)
#define vlog(v, fmt, ...) do{ if(DEBUG == v) fprintf(stderr, ("[%s:%d(%s)] " fmt), __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__); }while(0)
#else
#define dlog(fmt, ...) do { ; } while(0)
#define vlog(fmt, ...) do { ; } while(0)
#endif
