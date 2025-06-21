#include <pcap.h>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "ether.h"



void EtherFillEtherHeader(ether_header *eth, uint8_t src_mac[], uint8_t dest_mac[], uint16_t ether_type)
{
    memcpy(eth->ether_dhost, dest_mac, ETHER_ADDR_LEN);
    memcpy(eth->ether_shost, src_mac, ETHER_ADDR_LEN);
    eth->ether_type = htons(ether_type);
}

void EtherFillProtocol(Protocol *proto, std::string payload)
{
    memcpy(proto->MessageType, "FPGA_not_taken", PROTOCOL_MESSAGE_TYPE_LEN);

    char temp[256];
    sprintf(temp, "%04zu_not_taken", payload.length());
    memcpy(proto->MessageLength, temp, PROTOCOL_MESSAGE_LENGTH_LEN);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = "eth0";
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }

    uint8_t src_mac[ETHER_ADDR_LEN]  = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t dest_mac[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    uint8_t frame[ETHER_MAX_FRAME_LEN];

    for (int i = 0; i < 10; i++) {
        // Ethernet Header
        ether_header *eth = (ether_header *)frame;
        EtherFillEtherHeader(eth, src_mac, dest_mac, ETHER_ETHER_TYPE);

        // Custom protocol header
        Protocol *proto = (Protocol *)(frame + ETHER_HEADER_LEN);
        std::stringstream ss;
        ss << "Hello, Router! Packet #" << (i + 1);
        std::string payload = ss.str();
        EtherFillProtocol(proto, payload);

        // Payload
        uint8_t *payload_ptr = frame + ETHER_HEADER_LEN + ETHER_PROTOCOL_LEN;
        memcpy(payload_ptr, payload.c_str(), payload.length());

        // Total frame length
        size_t frame_len = ETHER_HEADER_LEN + ETHER_PROTOCOL_LEN + payload.length();

        // the `pcap_sendpacket` function or the NIC card sets the (Preamble, SFD, and FCS)
        if (pcap_sendpacket(handle, frame, frame_len) != 0) {
            fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return 2;
        }
        memset(frame, 0, 1500);
    }

    printf("Packets sent!\n");
    pcap_close(handle);
    return 0;
}
