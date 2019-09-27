#include <pcap.h>
#include "pcap.h"
#define min(a,b) (((a)<(b))?(a):(b))

void printMacAddress(u_char * arr) {
    for(int i=0;i<MAC_ADDR_LEN;i++) {
        printf("%02x", arr[i]);
        if(i < MAC_ADDR_LEN - 1)
            printf(":");
    }
}

void printIPAddress(u_char * arr) {
    for(int i=0;i<IP_ADDR_LEN;i++) {
        printf("%u", arr[i]);
        if(i < IP_ADDR_LEN - 1)
            printf(".");
    }
}

void DataLinkLayer(const u_char * packet, int len){
    struct Ether_Header * ether_header = (struct Ether_Header *)packet;

    printf("[ Data Link Layer : Ethernet ]\n");
    printf("source MAC : ");
    printMacAddress(ether_header -> src_mac);
    printf("\n");
    printf("destination MAC : ");
    printMacAddress(ether_header -> des_mac);
    printf("\n\n");
    
    switch(ntohs(ether_header -> ether_type)) {
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
    printf("source IP : ");
    printIPAddress(ip_header->src_ip);
    printf("\n");
    printf("destination IP : ");
    printIPAddress(ip_header->des_ip);
    printf("\n\n");

    switch(ip_header -> protocol) {
    case TCP:
        printf("[ Transport Layer : TCP ]\n");
        TransportLayer(packet, len, start + ((ip_header->etc[0] & 0x0F) << 2));
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
    printf("source PORT : %u\n", ntohs(tcp_header -> src_port));
    printf("destination PORT : %u\n", ntohs(tcp_header -> des_port));
    printf("\n");

    printf("[ Payload ]\n");
    start += ((int)tcp_header->etc[8] & 0xF0) >> 2;
    for(int i = start; i < min(start + 32, len); i++) {
        printf("%02x ", packet[i]);
        if((i-start)==15) printf("\n");
    }
}