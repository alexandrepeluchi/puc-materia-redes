/* Headers de entrada/saida, string, etc */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

/* Macros para obter acesso as arrays de dados auxiliares associados a mensagem de um cabeçalho */
#include <sys/socket.h>

/* Familia de Protocolos Internet */
#include <netinet/in.h>

/* Definições de Operações Internet */
#include <arpa/inet.h>

/* Opções para controle de arquivos */
#include <fcntl.h>

/* Headers IP e ICMP caso o SO seja o OpenBSD */
#if defined(__OpenBSD__)
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif

/* Headers IP e ICMP caso o SO seja o Linux */
#if defined(__linux__)
#include <linux/ip.h>
#include <linux/icmp.h>
#endif

/* Declarações para espera (wait) */
#include <sys/wait.h>

#define IP_MAXPACKET 65535

/* Declarações das Structs de cabeçalhos caso o SO seja o OpenBSD */
#if defined(__OpenBSD__)
struct packet
{
        struct icmp *hdricmp;
        struct ip *hdrip;
        char *data;
};
#endif

/* Declarações das Structs de cabeçalhos caso o SO seja o Linux */
#if defined(__linux__)
struct packet
{
        struct icmphdr *hdricmp;
        struct iphdr *hdrip;
        char *data;
};
struct iphdr *build_ip(struct iphdr *, const char *, const char *);
struct icmphdr *build_icmp(struct icmphdr *);
#endif

/*
 * in_cksum ->
 *      Checksum routine for Internet Protocol family headers (C Version)]
 *      Recebe a informação de um endereço e o tamanho do conteudo em seguida
 *      Gera uma assinatura/hash de um conteudo, porque é utilizado no cabeçalho do ICMP
 *      Tanto na origem quanto no destino, basta verificar a assinatura para saber se o conteudo em ambos é o mesmo
 *      Se forem idênticos e chegaram de forma integra, é garantido que é o mesmo conteudo
 *      Retorna um inteiro de 2 bytes
 */
unsigned short in_cksum(unsigned short *addr, int len)
{
        /* Declarações de variaveis */
        register int sum = 0;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;

        /*
         * Nosso algoritmo é simples, usando um acumulador de 32 bits (soma), 
         * adicionamos palavras sequenciais de 16 bits a ele e, no final, dobramos 
         * todos os bits de transporte dos 16 bits superiores para os 16 bits inferiores.
         */
        while (nleft > 1)
        {
                sum += *w++;
                nleft -= 2;
        }

        /* limpa um byte ímpar, se necessário*/
        if (nleft == 1)
        {
                *(u_char *)(&answer) = *(u_char *)w;
                sum += answer;
        }

        /* adicione o transporte de retorno dos 16 bits principais para os 16 bits inferiores */
        sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
        sum += (sum >> 16);                 /* add carry */
        answer = ~sum;                      /* truncar para 16 bits */
        return (answer);
}

/* Recebe o icmp de resposta (echo reply) com dados */
int rcvreply(void) {

        struct sockaddr saddr;
        size_t len = 0, nbytes = -1, errorCode = -1;
        int sd = -1;
        unsigned char *buffer;

        if ((sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
                perror("Unable to create the socket");
                exit(1);
        }

        if (fcntl(sd, F_SETFL, O_SYNC) != 0) {
                perror("Request synchronous writes!");
        }

        printf("\n\n[+] Fork - Successful Socket Raw Connection");

        /* The buffer to receive payload (data) */
        buffer = (unsigned char *) malloc(IP_MAXPACKET);
        memset(buffer, 0, IP_MAXPACKET);

        len = sizeof(struct sockaddr);

        do {
                if ((nbytes = recvfrom(sd, buffer, IP_MAXPACKET, 0, (struct sockaddr *) &saddr, (socklen_t *) &len)) == errorCode) {
                        perror("receive error ...");
                } 
                else 
                {
                        printf("\n[+] Received an ICMP echo reply packet  with data ...\n");
                        printf("\nNumber of bytes: %ld\n", nbytes);
                        printf("Packet Data: %s", buffer);                               
                }
                memset(buffer, 0, IP_MAXPACKET);
        } while (nbytes > 0);
        free(buffer);
        return(close(sd));
}

/* IP and ICMP package forger 
 Fornece os valores padrões para os cabeçalhos caso o SO seja o OpenBSD */
#if defined(__OpenBSD__)
    /* Construção do cabeçalho IP com seus valores default */
    struct ip * build_ip(struct ip *ip, const char *addr, const char *hostAddr);
{
        ip->ip_hl = 5;
        ip->ip_v = 4;
        ip->ip_tos = 0;
        ip->ip_len = htons(sizeof(*ip) + sizeof(struct icmp));
        ip->ip_id = htons(getpid());
        ip->ip_ttl = 255;
        ip->ip_p = IPPROTO_ICMP;
        ip->ip_src.s_addr = inet_addr(hostAddr);
        ip->ip_dst.s_addr = inet_addr(addr);
        ip->ip_sum = 0;
        return (ip);
}

/* Construção do cabeçalho ICMP com seus valores default */
struct icmp *build_icmp(struct icmp *icmp)
{
        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
        icmp->icmp_hun.ih_idseq.icd_id = 0;
        icmp->icmp_hun.ih_idseq.icd_seq = 0;
        icmp->icmp_cksum = 0;
        return (icmp);
}
#endif

/* Fornece os valores padrões para os cabeçalhos caso o SO seja o Linux */
#if defined(__linux__)
/* Construção do cabeçalho IP com seus valores default */
struct iphdr *build_ip(struct iphdr *ip, const char *addr, const char *hostAddr)
{
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(*ip) + sizeof(struct icmphdr));
        ip->id = htons(getpid());
        ip->ttl = 255;
        ip->protocol = IPPROTO_ICMP;
        ip->saddr = inet_addr(hostAddr);
        ip->daddr = inet_addr(addr);
        ip->check = 0;
        return (ip);
}

/* Construção do cabeçalho ICMP com seus valores default */
struct icmphdr *build_icmp(struct icmphdr *icmp)
{
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->un.echo.id = 0;
        icmp->un.echo.sequence = 0;
        icmp->checksum = 0;
        return (icmp);
}
#endif