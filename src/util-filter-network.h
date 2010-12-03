int parse_network (char *net_s, struct in6_addr *network);
int parse_netmask (char *f, int type, struct in6_addr *netmask);
void parse_nets(const char *s_net, struct fmask *network);
