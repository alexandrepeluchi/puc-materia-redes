#if defined(__linux__)
struct iphdr *build_ip(struct iphdr *, const char *, const char *);
struct icmphdr *build_icmp(struct icmphdr *);
#endif

#if defined(__OpenBSD__)
struct ip * build_ip(struct ip *ip, const char *addr);
struct ip * build_ip(struct ip *ip, const char *addr, const char *hostAddr);
struct icmp *build_icmp(struct icmp *icmp);
#endif

int rcvreply(void);

/* Declaração de Checksum */
unsigned short in_cksum(unsigned short *, int);

void display(void *buf, int bytes);