/*****************************************************************************/
/*** Use the ICMP protocol to request echo from destination.               ***/
/***                                                                       ***/
/*** This code sends an ...                                                ***/
/*** Tested along with tcpdump to validate that packets are being          ***/
/*** exchanged between hosts.                                              ***/
/*****************************************************************************/
// Compilar com: clang -Wall templateRAW.c -o rawtest
//
// Codigo compativel com OpenBSD e Linux
// Correa: correa@pucpcaldas.br
// Sniffer: doas tcpdump -nettti urtwn0 -n host ip_addr_of_dest
//          doas tcpdump -nettti urtwn0 -n dst host ip_addr_of_dest
// Run: doas ./rawtest
//      informe ip_addr_of_dest
// Obs.: No Linux, utilize sudo para substituir o doas

// Headers de entrada/saida, string, etc
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

// Macros para obter acesso as arrays de dados auxiliares associados a mensagem de um cabeçalho
#include <sys/socket.h>

// Familia de Protocolos Internet
#include <netinet/in.h>

// Definições de Operações Internet
#include <arpa/inet.h>

// Opções para controle de arquivos
#include <fcntl.h>

// Headers IP e ICMP caso o SO seja o OpenBSD
#if defined(__OpenBSD__)
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif

// Headers IP e ICMP caso o SO seja o Linux
#if defined(__linux__)
#include <linux/ip.h>
#include <linux/icmp.h>
#endif

// Declarações para espera (wait)
#include <sys/wait.h>

#define IP_MAXPACKET 65535

int rcvreply(void);

// Declarações das Structs de cabeçalhos caso o SO seja o OpenBSD
#if defined(__OpenBSD__)
struct packet
{
        struct icmp *hdricmp;
        struct ip *hdrip;
        char *data;
};
struct ip *build_ip(struct ip *, const char *);
struct icmp *build_icmp(struct icmp *);
#endif

// Declarações das Structs de cabeçalhos caso o SO seja o Linux
#if defined(__linux__)
struct packet
{
        struct icmphdr *hdricmp;
        struct iphdr *hdrip;
        char *data;
};
struct iphdr *build_ip(struct iphdr *, const char *);
struct icmphdr *build_icmp(struct icmphdr *);
#endif

// Definicao de struct para calculo de tempo de execução
struct timeval start, end;

// Pede o Ip do Host
const char *hostAddr;

// Declaração de Checksum
unsigned short in_cksum(unsigned short *, int);

// Ponto de entrada da aplicação
int main(int argc, char *argv[])
{
        (void)argc; (void)argv;

        // Fornece um endereço de socket IPv4, para permitir a comunicação com outros hosts em uma rede TCP/IP
        struct sockaddr_in serv;

        // Definição das structs caso o SO seja OpenBSD
#if defined(__OpenBSD__)
        struct ip *ip;
        struct icmp *icmp;
#endif
        // Definição das structs caso o SO seja Linux
#if defined(__linux__)
        struct iphdr *ip;
        struct icmphdr *icmp;
#endif
        // Definição das variáveis e ponteiros
        unsigned int dst[4] = {0};
        size_t len;
        int sd = -1, optval = 1;
        const char *addr, *packet;

        /*
         * Semelhante a função malloc
         * Malloc vai até a memória ram e pega a quantidade de bytes da área de memória e retorna os ponteiros
         * Mas é preciso utilizar o memset após, para limpar toda essa área de memória alocada para não ter lixo
         * Calloc faz a mesma coisa mas de uma vez, não é preciso chamar memset a memória é limpa automaticamente
         */
        addr = (char *)calloc(1, 16 * sizeof(*addr));
        hostAddr = (char *)calloc(1, 16 * sizeof(*hostAddr));

        // Recebe IP para executar o Ping
        printf("\nSending an ICMP echo request packet ...\nEnter the host address: ");
        scanf("%16s", (char *)hostAddr);

        // Verifica se é um endereço IP válido, senão encerra a aplicação
        if (sscanf(hostAddr, "%u.%u.%u.%u", &dst[0], &dst[1], &dst[2], &dst[3]) != 4)
        {
                perror("Invalid host ip address");
                return (0);
        }

        // Recebe IP para executar o Ping
        printf("\nEnter the address to ping: ");
        scanf("%16s", (char *)addr);

        // Verifica se é um endereço IP válido, senão encerra a aplicação
        if (sscanf(addr, "%u.%u.%u.%u", &dst[0], &dst[1], &dst[2], &dst[3]) != 4)
        {
                perror("Invalid ip address");
                return (0);
        }

        // Printa o endereço de IP alvo
        printf("\nTarget address: %u.%u.%u.%u ... ", dst[0], dst[1], dst[2], dst[3]);

        // Reserva e limpa área de memória
        packet = (char *)calloc(1, sizeof(*ip) + sizeof(*icmp));

        // Definição das structs
#if defined(__OpenBSD__)
        ip = (struct ip *)packet;
        icmp = (struct icmp *)(packet + sizeof(*ip));
#endif
        // Definição das structs
#if defined(__linux__)
        ip = (struct iphdr *)packet;
        icmp = (struct icmphdr *)(packet + sizeof(*ip));
#endif
        // Funções para construir os cabeçalhos IP e ICMP com seus valores padrões
        build_ip(ip, addr);
        build_icmp(icmp);

        /*
        * Condição que tenta criar a conexão com o Socket Raw, caso ocorra algum erro neste processo
        * a aplicação é encerrada
        */
        if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
        {
                perror("Unable to create the socket");
                exit(1);
        }

        /*
         * Fornece a uma aplicação os meios para controlar o comportamento do Socket.
         * É possivel utilizar após utilizar o setsockopt(), alocar espaço no buffer,
         * controlar timeouts, permitir broadcast de dados, etc.
         */
        setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

        /*
         * Seta as flags do descritor do arquivo (File), como o terceiro arquivo é diferente de 0,
         * a conexão será encerrado após a execução bem sucedida de alguma função header fcntl 
         */
        if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0)
        {
                perror("Request nonblocking I/O");
        }

        /*
         * Utilizando função in_cksum (Checksum), para gerar as assinatudas dos cabeçalhos IP e ICMP
         * caso o SO seja o OpenBSD
         */
#if defined(__OpenBSD__)
        icmp->icmp_cksum = in_cksum((unsigned short *)icmp, sizeof(*icmp));
        ip->ip_sum = in_cksum((unsigned short *)ip, sizeof(*ip));
        len = ntohs(ip->ip_len);
#endif
        /*
         * Utilizando função in_cksum (Checksum), para gerar as assinatudas dos cabeçalhos IP e ICMP
         * caso o SO seja o OpenBSD
         */
#if defined(__linux__)
        icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(*icmp));
        ip->check = in_cksum((unsigned short *)ip, sizeof(*ip));
        len = ntohs(ip->tot_len);
#endif
        /* 
         * O primeiro argumento pega a estrutura 'serv', o segundo escreve \0 em toda a área de memória reservada,
         * e o terceiro argumento o sizeof, retorna o tamanho da área de memória reservada
         */
        memset(&serv, '\0', sizeof(struct sockaddr_in));

        // Código para familia de endereços
        serv.sin_family = PF_INET;

        /* 
         * Endereço IP do host, para código de servidor, sempre será o endereço IP da máquina na qual o
         * servidor está sendo executado
         */
        serv.sin_addr.s_addr = inet_addr(addr);

        gettimeofday(&start, NULL);

        if (fork() == 0)
        {
                /*
                 * Cria um processo filho, que deriva do programa pai, aqui deverá ser inserido a lógica
                 * de recepção do ping no caso o recvfrom()
                 */
                rcvreply();
        }
        else
        {
                /*
                 * Processo pai é executado, enviando uma mensagem no socket
                 */
                sendto(sd, packet, len, 0, (struct sockaddr *)&serv, sizeof(struct sockaddr));
                printf("\n[+] Package sent [parent process id: %u].\n", getpid());
        }
        wait(0);

        // Encerra a conexão do Socket
        close(sd);

        // Finaliza aplicação
        return (0);
}

// Recebe o icmp de resposta (echo reply) com dados
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

        // The buffer to receive payload (data)
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
                        gettimeofday(&end, NULL);
                        printf("\n\nTime interval between Sent and Receive packet: %ld ms\n", ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)));                       
                
                }
                printf("Teste");
                memset(buffer, 0, IP_MAXPACKET);
        } while (nbytes > 0);
        free(buffer);
        return(close(sd));
}

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
        // Declarações de variaveis
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

/* IP and ICMP package forger */
// Fornece os valores padrões para os cabeçalhos caso o SO seja o OpenBSD
#if defined(__OpenBSD__)
    // Construção do cabeçalho IP com seus valores default
    struct ip *
    build_ip(struct ip *ip, const char *addr)
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

// Construção do cabeçalho ICMP com seus valores default
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

// Fornece os valores padrões para os cabeçalhos caso o SO seja o Linux
#if defined(__linux__)
// Construção do cabeçalho IP com seus valores default
struct iphdr *build_ip(struct iphdr *ip, const char *addr)
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

// Construção do cabeçalho ICMP com seus valores default
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
