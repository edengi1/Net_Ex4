// header files
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>,
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <unistd.h>
#include <pcap.h>
#include "header.h"

// define
#define ICMP_HDRLN_4 4
#define TRUE 1
#define EXIT 0

void print_packet(char*, int);
int icmp = 0;

// main function
int main() {
    int PACLN = IP_MAXPACKET;
    struct sockaddr saddr;
    struct ifreq ethreq;
    struct packet_mreq m;

    int sock;
    if((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
        perror("\n Raw socket create failed.\n");
        exit(TRUE);
    }

    char buffer[IP_MAXPACKET];
    socklen_t t;
    while(TRUE) {
        bzero(buffer, IP_MAXPACKET);
        t = sizeof(saddr);
        int size = recvfrom(sock, buffer, PACLN, 0, &saddr, &t);
        if(size >= 0) {
        struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        struct sockaddr_in src, dest;

        if(iph -> protocol == IPPROTO_ICMP){
            printf("\nICMP packet %d, data size: %d\n", ++icmp, size);
            memset(&src, 0, sizeof(src));
            src.sin_addr.s_addr = iph -> saddr;

            memset(&dest, 0 ,sizeof(dest));
            dest.sin_addr.s_addr = iph -> daddr;

            puts("IP Header");
            printf("Source IP: %s\n", inet_ntoa(src.sin_addr));
            printf("Dest IP:%s\n", inet_ntoa(dest.sin_addr));

            int iphdrlen = iph-> ihl * ICMP_HDRLN_4;
            struct sniff_icmp *icmph = (struct icmphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
           
            puts("ICMP Header");
            printf("Type: %d\n", (unsigned int)(icmph -> icmp_type));
            printf("Code: %d\n", icmph -> icmp_code);
        }

        // close socket
        close(sock);
        return EXIT;
        }
    }
}
