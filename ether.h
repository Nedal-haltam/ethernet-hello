#pragma once

#include <iostream>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <cstring>

#define CallBackType(VariableName) void (*VariableName)(u_char *, const struct pcap_pkthdr *, const u_char *)

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
                    inet_ntop(AF_INET, &((struct sockaddr_in *)addr->addr)->sin_addr, ip, sizeof(ip));
                    std::cout << "   - IP: " << ip << std::endl;
                }
                if (addr->netmask) {
                    char netmask[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((struct sockaddr_in *)addr->netmask)->sin_addr, netmask, sizeof(netmask));
                    std::cout << "   - Netmask: " << netmask << std::endl;
                }
            }
        }
        std::cout << "-----------------------------" << std::endl;
    }
}

void PacketHandler_Printer(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    const char* user_info = reinterpret_cast<const char*>(user);
    
    const struct ether_header *eth = (struct ether_header *)packet;
    std::cout << "[User Info]: " << user_info << std::endl;
    std::cout << "Ethernet Frame:" << std::endl;
    std::cout << "  Src MAC: " << ether_ntoa((const struct ether_addr *)eth->ether_shost) << std::endl;
    std::cout << "  Dst MAC: " << ether_ntoa((const struct ether_addr *)eth->ether_dhost) << std::endl;
    std::cout << "  EtherType: 0x" << std::hex << ntohs(eth->ether_type) << std::dec << std::endl;

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        const struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));
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
    pcap_freealldevs(devs);
}

pcap_t * EtherOpenDevice(pcap_if_t *devs, pcap_if_t *device, char *errbuf)
{
    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Couldn't open device: " << errbuf << std::endl;
        pcap_freealldevs(devs);
        exit(EXIT_FAILURE);
    }
    return handle;
}

void EtherSetFilter(pcap_t *handle, const char *filter_exp)
{
    struct bpf_program fp;
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
        pcap_freealldevs(devs);
        exit(EXIT_FAILURE);
    }
    return dumper;
}

void EtherCapturePackets(pcap_if_t *devs, pcap_t *handle, int num_packets, void (*callback)(u_char *, const struct pcap_pkthdr *, const u_char *), u_char *user_arg)
{
    if (callback == NULL)
        callback = PacketHandler_Printer;
    if (pcap_loop(handle, num_packets, callback, user_arg) < 0) {
        std::cerr << "Error capturing packets: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        pcap_freealldevs(devs);
        exit(EXIT_FAILURE);
    }
}