#include <iostream>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <cstring>

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
    pcap_if_t *devs;

    // Get a list of devices
    if (pcap_findalldevs(&devs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    if (devs == nullptr) {
        std::cerr << "No devices found." << std::endl;
        return 1;
    }

    // Use the first device found
    pcap_if_t *device = devs;
    std::cout << "Using device: " << device->name << std::endl;

    // Open device for capturing
    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Couldn't open device: " << errbuf << std::endl;
        pcap_freealldevs(devs);
        return 1;
    }
    // TODO: filter packets
    // struct bpf_program fp;
    // pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN);
    // pcap_setfilter(handle, &fp);

    // Capture 10 packets
    USER_TYPE user_info = "My Custom Tag";
    pcap_loop(handle, 10, packet_handler, (u_char*)user_info);

    // Clean up
    pcap_close(handle);
    pcap_freealldevs(devs);

    return 0;
}
