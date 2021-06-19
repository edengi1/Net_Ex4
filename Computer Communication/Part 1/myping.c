#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()
#include "header.h" // checksum()

// IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8 

// Checksum algo
unsigned short checksum(unsigned short * paddress, int len);
//i.e the gateway or ping to google.com for their ip-address

#define DESTINATION_IP "8.8.8.8"

int main (){

  struct sniff_icmp icmphdr; // ICMP-header

  char data[IP_MAXPACKET] = "This is a ping.\n";

  int datalen = strlen(data) + 1;

  /*===============ICMP header ===================
    Message Type (8 bits): ICMP_ECHO_REQUEST */

  icmphdr.icmp_type = ICMP_ECHO_REQ;

  // Message Code (8 bits): echo request
  icmphdr.icmp_code = 0;

  /* Identifier (16 bits): some number to trace the response.
   It will be copied to the response packet and used to map response to the request sent earlier.
   Thus, it serves as a Transaction-ID when we need to make "ping" */

  icmphdr.icmp_id = 18; // hai

  // Sequence Number (16 bits): starts at 0
  icmphdr.icmp_seq = 0;

  // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
  icmphdr.icmp_cksum = 0;

  // Combine the packet 
  char packet[IP_MAXPACKET];

  // Next, ICMP header
  memcpy ((packet), &icmphdr, ICMP_HDRLEN);

  // After ICMP header, add the ICMP data.
  memcpy (packet + ICMP_HDRLEN, data, datalen);

  // Calculate the ICMP header checksum
  icmphdr.icmp_cksum = checksum((unsigned short *) (packet), ICMP_HDRLEN + datalen);
  memcpy ((packet), &icmphdr, ICMP_HDRLEN);

  struct sockaddr_in dest_in;
  memset (&dest_in, 0, sizeof (struct sockaddr_in));
  dest_in.sin_family = AF_INET;

  // The port is irrelant for Networking and therefore was zeroed.
  dest_in.sin_addr.s_addr = inet_addr(DESTINATION_IP);

  // Create raw socket for IP-RAW='  (make IP-header by yourself)
  int sock = -1;
  if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1){
    fprintf (stderr, "socket() failed with error: %d", errno);
    fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
    return -1;
  }
  struct timeval start, end;
  gettimeofday(&start, NULL);

  // Send the packet using sendto() for sending datagrams.
  if (sendto (sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)  {
    fprintf (stderr, "sendto() failed with error: %d", errno);
    return -1;
  }

    printf ("Send to %s\n", DESTINATION_IP);
    // Close the raw socket descriptor.
    while(1){
        char buffer[IP_MAXPACKET] = {0};
        int t = sizeof(dest_in);
        int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &dest_in, (socklen_t *) &t);
        if (bytes < 0) {
            perror("error");
          }
        else{
            gettimeofday(&end, NULL);
            double dt_micro = (double) end.tv_usec - start.tv_usec;
            double dt_milis = dt_micro / 1000.;
            printf("Received from %s\n", DESTINATION_IP);
            printf("RTT: %f milliseconds\n", dt_milis);
            printf("RTT: %.0f microseconds\n", dt_micro);
            break;
          }
    }   

    close(sock);
    return 0;
}

