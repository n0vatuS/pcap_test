#pragma once

// Length
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define PORT_ADDR_LEN 2

// EtherType
#define IP_v4_HEADER 0x0800
#define ARP_HEADER 0x0806
#define IP_v6_HEADER 0x86DD

// IP Protocal
#define TCP 0x06
#define UDP 0x11
#define SCTP 0x84

// header size
#define DATALINK_HEADER_SIZE 14

struct Ether_Header {
    u_char des_mac[MAC_ADDR_LEN];
    u_char src_mac[MAC_ADDR_LEN];
    u_short ether_type;
};

struct IP_Header {
    u_char etc[9];
    u_char protocol;
    u_char header_checksum[2];
    u_char src_ip[IP_ADDR_LEN];
    u_char des_ip[IP_ADDR_LEN];
};

struct TCP_Header {
    u_short src_port;
    u_short des_port;
    u_char etc[10];
};

void DataLinkLayer(const u_char * packet, int len);
void NetworkLayer(const u_char * packet, int len, int start);
void TransportLayer(const u_char * packet, int len, int start);
