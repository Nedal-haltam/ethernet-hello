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

#pragma pack(push, 1)
struct custom_proto {
    uint8_t MessageType[4];
    uint8_t MessageLength[4];
};
#pragma pack(pop)

#define ETHER_TYPE 0x88B5

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = "eth0"; // Change this to your interface
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }

    uint8_t src_mac[6]  = {0x00, 0x15, 0x5D, 0x0C, 0xD8, 0x25};
    // uint8_t src_mac[6]  = {0x00, 0x15, 0x5D, 0x5D, 0xC8, 0x1A};

    uint8_t dest_mac[6] = {0x00, 0x15, 0x5D, 0x9F, 0x6A, 0xFC};
    // uint8_t dest_mac[6] = {0x00, 0x15, 0x5D, 0xCE, 0x7A, 0xCB};


    uint8_t frame[1500];

    for (int i = 0; i < 10; i++) {
        // Ethernet Header
        struct ether_header *eth = (struct ether_header *)frame;
        memcpy(eth->ether_dhost, dest_mac, 6);
        memcpy(eth->ether_shost, src_mac, 6);
        eth->ether_type = htons(ETHER_TYPE); // Custom EtherType

        // Custom protocol header
        struct custom_proto *proto = (custom_proto *)(frame + ETHERNET_HEADER_LENGTH);
        memcpy(proto->MessageType, "FPGA", 4);
        std::stringstream ss;
        ss << "Hello, Router! Packet #" << (i + 1);
        std::string payload = ss.str();
        char temp[5];
        sprintf(temp, "%04zu", payload.length());
        memcpy(proto->MessageLength, temp, 4);

        // Payload
        uint8_t *payload_ptr = frame + ETHERNET_HEADER_LENGTH + sizeof(custom_proto);
        memcpy(payload_ptr, payload.c_str(), payload.length());

        // Total frame length
        size_t frame_len = ETHERNET_HEADER_LENGTH + sizeof(custom_proto) + payload.length();

        // the `pcap_sendpacket` function sends the Preamble, SFD, and FCS
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
