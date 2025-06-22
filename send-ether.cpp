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
#include <netinet/udp.h>  // for struct udphdr
#include <netinet/ip.h>   // for struct ip


void SendRawPacket(pcap_t* handle, uint8_t frame[], std::string payload, uint8_t src_mac[], uint8_t dest_mac[])
{
    // Ethernet Header
    ether_header *eth = (ether_header *)frame;
    EtherFillEtherHeader(eth, src_mac, dest_mac, ETHER_ETHER_TYPE);

    // Custom protocol header
    Protocol *proto = (Protocol *)(frame + ETHER_HEADER_LEN);
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
        exit(EXIT_FAILURE);
    }
}

#define ETHER_TYPE_IP 0x0800
void SendIPPacket(pcap_t* handle, uint8_t frame[], std::string payload, uint8_t src_mac[], uint8_t dest_mac[])
{
    // Ethernet header
    ether_header *eth = (ether_header *)frame;
    EtherFillEtherHeader(eth, src_mac, dest_mac, ETHER_TYPE_IP);

    // IP header
    struct ip *ip = (struct ip *)(frame + ETHER_HEADER_LEN);
    ip->ip_hl = 5;
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_len = htons(ETHER_IP_LEN + ETHER_UDP_HEADER_LEN + payload.length());
    ip->ip_id = htons(54321);
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_UDP;
    ip->ip_sum = 0;  // Let’s skip checksum for simplicity
    ip->ip_src.s_addr = inet_addr("192.168.1.10");
    ip->ip_dst.s_addr = inet_addr("192.168.1.5");

    // UDP header
    struct udphdr *udp = (struct udphdr *)(frame + ETHER_HEADER_LEN + ETHER_IP_LEN);
    udp->uh_sport = htons(12345);
    udp->uh_dport = htons(8080);
    udp->uh_ulen = htons(ETHER_UDP_HEADER_LEN + payload.length());
    udp->uh_sum = 0;

    // UDP payload
    uint8_t *payload_ptr = frame + ETHER_HEADER_LEN + ETHER_IP_LEN + ETHER_UDP_HEADER_LEN;
    memcpy(payload_ptr, payload.c_str(), payload.length());

    int frame_len = ETHER_HEADER_LEN + ETHER_IP_LEN + ETHER_UDP_HEADER_LEN + payload.length();

    // the `pcap_sendpacket` function or the NIC card sets the (Preamble, SFD, and FCS)
    if (pcap_sendpacket(handle, frame, frame_len) != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
}


int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* dev;
    MODE mode = MODE::RAW_ETHER;
    if (mode == MODE::IP)
    {
        // TODO: fix wireless interface to be able to send
        // const char *dev = "wlan0";  // Interface
        dev = "eth0";
    }
    else if (mode == MODE::RAW_ETHER)
    {
        dev = "eth0";
    }
    pcap_t *handle = EtherOpenDevice(NULL, dev, errbuf, PROMISC::SEND);


    uint8_t src_mac[ETHER_ADDR_LEN]  = {0x00, 0x15, 0x5D, 0x5D, 0xC8, 0x1A};
    uint8_t dest_mac[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    uint8_t frame[ETHER_MAX_FRAME_LEN] = {0};

    for (int i = 0; i < 10; i++) {
        std::stringstream ss;
        ss << "Hello, Router! Packet #" << (i + 1);
        std::string payload = ss.str();
        if (mode == MODE::IP)
            SendIPPacket(handle, frame, payload, src_mac, dest_mac);
        else if (mode == MODE::RAW_ETHER)
            SendRawPacket(handle, frame, payload, src_mac, dest_mac);

        memset(frame, 0, ETHER_MAX_FRAME_LEN);
    }

    printf("Packets sent!\n");
    pcap_close(handle);
    return 0;
}
