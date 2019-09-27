#include <pcap.h>
#include <stdint.h>
#include "pcap.h"
#define min(a,b) (((a)<(b))?(a):(b))

uint16_t my_ntohs(uint16_t n)
{
    return ((n & 0xFF00) >> 8) | ((n & 0x00FF) << 8);
}

void DataLinkLayer(const u_char * packet, int len){
    struct Ether_Header * ether_header = (struct Ether_Header *)packet;

    printf("[ Data Link Layer : Ethernet ]\n");
    printf("source MAC : ");
    for(int i=0;i<MAC_ADDR_LEN;i++) {
        printf("%02x", ether_header -> src_mac[i]);
        if(i < MAC_ADDR_LEN - 1)
            printf(":");
    }
    printf("\n");
    printf("destination MAC : ");
    for(int i=0;i<MAC_ADDR_LEN;i++) {
        printf("%02x", ether_header -> des_mac[i]);
        if(i < MAC_ADDR_LEN - 1)
            printf(":");
    }
    printf("\n\n");
    
    switch(my_ntohs(ether_header -> ether_type)) {
    case IP_v4_HEADER: {
        printf("[ Network Layer : IP_v4 ]\n");
        NetworkLayer(packet, len, DATALINK_HEADER_SIZE);
        break;
    }
    case ARP_HEADER:
        printf("[ Network Layer : ARP ]\n");
        break;
    case IP_v6_HEADER:
        printf("[ Network Layer : IP_v6 ]\n");
        break;
    }
    printf("\n\n");
}

void NetworkLayer(const u_char * packet, int len, int start){
    struct IP_Header * ip_header = (struct IP_Header *)(packet+start);
    printf("source IP : %d.%d.%d.%d\n",ip_header -> src_ip[0], ip_header -> src_ip[1], ip_header -> src_ip[2], ip_header -> src_ip[3]);
    printf("destination IP : %d.%d.%d.%d\n",ip_header -> des_ip[0], ip_header -> des_ip[1], ip_header -> des_ip[2], ip_header -> des_ip[3]);
    printf("\n");

    switch(ip_header -> protocol) {
    case TCP:
        printf("[ Transport Layer : TCP ]\n");
        TransportLayer(packet, len, start + (((int)ip_header->etc[0] & 0x0F) << 2));
        break;
    case UDP:
        printf("[ Transport Layer : UDP ]\n");
        break;
    case SCTP:
        printf("[ Transport Layer : SCTP ]\n");
        break;
    }
}

void TransportLayer(const u_char * packet, int len, int start){
    struct TCP_Header * tcp_header = (struct TCP_Header *)(packet+start);
    printf("source PORT : %d\n", tcp_header -> src_port[0] << 8 | tcp_header -> src_port[1]);
    printf("destination PORT : %d\n", tcp_header -> des_port[0] << 8 | tcp_header -> des_port[1]);
    printf("\n");

    printf("[ Payload ]\n");
    start += ((int)tcp_header->etc[8] & 0xF0) >> 2;
    for(int i = start; i < min(start + 32, len); i++) {
        printf("%02x ", packet[i]);
        if((i-start)==15) printf("\n");
    }
}