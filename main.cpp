#include <stdio.h>
#include <memory.h>
#include <pcap.h>
#include "pcap.h"


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  int cnt = 0;

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (++cnt) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("-----------------------------------\n\n");
    printf("PACKET[%d] : %u bytes\n\n", cnt, header->caplen);
    DataLinkLayer(packet, header->caplen);
  }

  pcap_close(handle);
  return 0;
}
