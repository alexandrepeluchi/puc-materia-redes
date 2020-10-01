/*****************************************************************************/
/*** Use the ICMP protocol to request echo from destination.               ***/
/***                                                                       ***/
/*** This code sends an ...                                                ***/
/*** Tested along with tcpdump to validate that packets are being          ***/
/*** exchanged between hosts.                                              ***/
/*****************************************************************************/
/* Compilar com: clang -Wall templateRAW.c -o rawtest
 *
 * Codigo compativel com OpenBSD e Linux
 * Correa: correa@pucpcaldas.br
 * Sniffer: doas tcpdump -nettti urtwn0 -n host ip_addr_of_dest
 *          doas tcpdump -nettti urtwn0 -n dst host ip_addr_of_dest
 * Run: doas ./rawtest
 *      informe ip_addr_of_dest
 * Obs.: No Linux, utilize sudo para substituir o doas
 */

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

#include "raw.h"

/* Definicao de struct para calculo de tempo de execução */
struct timeval start, end;

/* Pede o Ip do Host */
const char *hostAddr;

/* Ponto de entrada da aplicação */
int main(int argc, char *argv[])
{
        /* Definição das structs caso o SO seja Linux */
#if defined(__linux__)
        struct iphdr *ip;
        struct icmphdr *icmp;
#endif
        /* Definição das structs caso o SO seja OpenBSD */
#if defined(__OpenBSD__)
        struct ip *ip;
        struct icmp *icmp;
#endif
        /* Definição das variáveis e ponteiros */
        unsigned int dst[4] = {0};
        size_t len;
        int sd = -1, optval = 1;
        const char *addr, *packet;

        /* Fornece um endereço de socket IPv4, para permitir a comunicação com outros hosts em uma rede TCP/IP */
        struct sockaddr_in serv;
        
        (void)argc; (void)argv;  

        /*
         * Semelhante a função malloc
         * Malloc vai até a memória ram e pega a quantidade de bytes da área de memória e retorna os ponteiros
         * Mas é preciso utilizar o memset após, para limpar toda essa área de memória alocada para não ter lixo
         * Calloc faz a mesma coisa mas de uma vez, não é preciso chamar memset a memória é limpa automaticamente
         */
        addr = (char *)calloc(1, 16 * sizeof(*addr));
        hostAddr = (char *)calloc(1, 16 * sizeof(*hostAddr));

        /* Recebe IP para executar o Ping */
        printf("\nSending an ICMP echo request packet ...\nEnter the host address: ");
        scanf("%16s", (char *)hostAddr);

        /* Verifica se é um endereço IP válido, senão encerra a aplicação */
        if (sscanf(hostAddr, "%u.%u.%u.%u", &dst[0], &dst[1], &dst[2], &dst[3]) != 4)
        {
                perror("Invalid host ip address");
                return (0);
        }

        /* Recebe IP para executar o Ping */
        printf("\nEnter the address to ping: ");
        scanf("%16s", (char *)addr);

        /* Verifica se é um endereço IP válido, senão encerra a aplicação */
        if (sscanf(addr, "%u.%u.%u.%u", &dst[0], &dst[1], &dst[2], &dst[3]) != 4)
        {
                perror("Invalid ip address");
                return (0);
        }

        /* Printa o endereço de IP alvo */
        printf("\nTarget address: %u.%u.%u.%u ... ", dst[0], dst[1], dst[2], dst[3]);

        /* Reserva e limpa área de memória */
        packet = (char *)calloc(1, sizeof(*ip) + sizeof(*icmp));

        /* Definição das structs */
#if defined(__OpenBSD__)
        ip = (struct ip *)packet;
        icmp = (struct icmp *)(packet + sizeof(*ip));
#endif
        /* Definição das structs */
#if defined(__linux__)
        ip = (struct iphdr *)packet;
        icmp = (struct icmphdr *)(packet + sizeof(*ip));
#endif
        /* Funções para construir os cabeçalhos IP e ICMP com seus valores padrões */
        build_ip(ip, addr, hostAddr);
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

        /* Código para familia de endereços */
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
        gettimeofday(&end, NULL);
        printf("\nTime interval between Sent and Receive packet: %ld ms\n", ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)));
        wait(0);

        /* Encerra a conexão do Socket */
        close(sd);

        /* Finaliza aplicação */
        return (0);
}

