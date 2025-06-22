#pragma once

#include <iostream>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <cstring>

#define CallBackType(VariableName) void (*VariableName)(u_char *, const pcap_pkthdr *, const u_char *)

// 8 + (6 + 6 + 2 + [PAYLOAD_LEN]) + 4
// we construct: (6 + 6 + 2 + [PAYLOAD_LEN]) -> (14 + [PAYLOAD_LEN])

#define ETHER_HEADER_LEN (sizeof(ether_header))
#define ETHER_IP_LEN (sizeof(struct ip))
#define ETHER_UDP_HEADER_LEN (sizeof(struct udphdr))
#define ETHER_PAYLOAD_LEN (1500)
#define ETHER_MAX_FRAME_LEN (ETHER_HEADER_LEN + ETHER_PAYLOAD_LEN)
#define ETHER_ETHER_TYPE (0x88B5)

#define PROTOCOL_MESSAGE_TYPE_LEN (5)
#define PROTOCOL_MESSAGE_LENGTH_LEN (5)
#pragma pack(push, 1)
struct Protocol {
    uint8_t MessageType[PROTOCOL_MESSAGE_TYPE_LEN];
    uint8_t MessageLength[PROTOCOL_MESSAGE_LENGTH_LEN];
};
#pragma pack(pop)
#define ETHER_PROTOCOL_LEN sizeof(Protocol)

enum PROMISC
{
    SEND, SNIFF
};

enum MODE
{
    IP,
    RAW_ETHER
};


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

void EtherPrintDevices(pcap_if_t *devs)
{
    std::cout << "Available devices:" << std::endl;
    for (pcap_if_t *d = devs; d != nullptr; d = d->next) {
        std::cout << "Device Name: " << "`" << d->name << "`" << std::endl;
        if (d->description) {
            std::cout << " - " << d->description << std::endl;
        }
        std::cout << " - Flags: " << d->flags << std::endl;
        if (d->addresses) {
            std::cout << " - Addresses:" << std::endl;
            for (pcap_addr_t *addr = d->addresses; addr != nullptr; addr = addr->next) {
                if (addr->addr) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((sockaddr_in *)addr->addr)->sin_addr, ip, sizeof(ip));
                    std::cout << "   - IP: " << ip << std::endl;
                }
                if (addr->netmask) {
                    char netmask[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((sockaddr_in *)addr->netmask)->sin_addr, netmask, sizeof(netmask));
                    std::cout << "   - Netmask: " << netmask << std::endl;
                }
            }
        }
        std::cout << "-----------------------------" << std::endl;
    }
}

void PacketHandler_Printer(u_char *user, const pcap_pkthdr *header, const u_char *packet) {
    static int counter = 1;
    const char* user_info = reinterpret_cast<const char*>(user);
    
    const ether_header *eth = (ether_header *)packet;
    std::cout << "Packet No." << counter++ << std::endl;
    std::cout << "[User Info]: " << user_info << std::endl;
    std::cout << "Ethernet Frame:" << std::endl;
    std::cout << "  Src MAC: " << ether_ntoa((const ether_addr *)eth->ether_shost) << std::endl;
    std::cout << "  Dst MAC: " << ether_ntoa((const ether_addr *)eth->ether_dhost) << std::endl;
    std::cout << "  EtherType: 0x" << std::hex << ntohs(eth->ether_type) << std::dec << std::endl;
    // Display payload (first 32 bytes or up to packet length)
    int payload_len = header->len - ETHER_HEADER_LEN;
    std::cout << "  Payload (" << payload_len << " bytes): ";
    const u_char* payload = packet + ETHER_HEADER_LEN;
    printf("payload as string: `");
    for (int i = 0; i < payload_len; i++)
        printf("%c", payload[i]);
    printf("`\n");

    std::cout << std::endl;
    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        const ip *ip_hdr = (ip *)(packet + sizeof(ether_header));
        std::cout << "  IP Src: " << inet_ntoa(ip_hdr->ip_src) << std::endl;
        std::cout << "  IP Dst: " << inet_ntoa(ip_hdr->ip_dst) << std::endl;
    }

    std::cout << "  Packet size: " << header->len << " bytes" << std::endl;
    std::cout << "-----------------------------" << std::endl;
}

pcap_if_t* EtherInitDevices()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs;
    // Get a list of devices
    if (pcap_findalldevs(&devs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    if (devs == nullptr) {
        std::cerr << "No devices found." << std::endl;
        exit(EXIT_FAILURE);
    }
    return devs;
}

void EtherClose(pcap_if_t *devs, pcap_t *handle)
{
    pcap_close(handle);
    if (devs)
        pcap_freealldevs(devs);
}

pcap_t* EtherOpenDevice(pcap_if_t *devs, const char* device, char *errbuf, PROMISC mode)
{
    pcap_t *handle = pcap_open_live(device, BUFSIZ, mode, 1000, errbuf);
    if (!handle) {
        std::cerr << "Couldn't open device: " << errbuf << std::endl;
        if (devs)
            pcap_freealldevs(devs);
        exit(EXIT_FAILURE);
    }
    return handle;
}

void EtherSetFilter(pcap_t *handle, const char *filter_exp)
{
    bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Couldn't parse filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter: " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
    pcap_freecode(&fp);
}

pcap_dumper_t* EtherDumpOpen(pcap_if_t *devs, pcap_t *handle, const char *filename)
{
    pcap_dumper_t *dumper = pcap_dump_open(handle, filename);
    if (!dumper) {
        std::cerr << "Couldn't open dump file: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        if (devs)
            pcap_freealldevs(devs);
        exit(EXIT_FAILURE);
    }
    return dumper;
}

void EtherCapturePackets(pcap_if_t *devs, pcap_t *handle, int num_packets, void (*callback)(u_char *, const pcap_pkthdr *, const u_char *), u_char *user_arg)
{
    if (callback == NULL)
        callback = PacketHandler_Printer;
    if (pcap_loop(handle, num_packets, callback, user_arg) < 0) {
        std::cerr << "Error capturing packets: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        if (devs)
            pcap_freealldevs(devs);
        exit(EXIT_FAILURE);
    }
}