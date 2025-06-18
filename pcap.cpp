#include <iostream>
#include "ether.h"

#define USER_TYPE const char*

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    USER_TYPE user_info = reinterpret_cast<USER_TYPE>(user);
    
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

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devs = EtherInitDevices();
    pcap_if_t *device = devs;
    std::cout << "Using device: " << device->name << std::endl;

    pcap_t *handle = EtherOpenDevice(device, device, errbuf);
    // TODO: filter packets
    // struct bpf_program fp;
    // pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN);
    // pcap_setfilter(handle, &fp);

    // Capture 10 packets
    EtherCapturePackets(devs, handle, 10, packet_handler, (u_char *)"User Info: Ethernet Hello");
    // Clean up
    EtherClose(devs, handle);
    return 0;
}
