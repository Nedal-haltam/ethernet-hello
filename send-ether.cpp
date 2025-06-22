#include <iostream>
#include <sstream>
#include "ether.h"

void SendRawPacket(pcap_t* handle, uint8_t frame[], std::string payload, uint8_t src_mac[], uint8_t dest_mac[])
{
    // Ethernet Header
    ether_header *eth = (ether_header *)frame;
    EtherFillEtherHeader(eth, src_mac, dest_mac, ETHER_COSTUME_ETHER_TYPE);

    // Custom protocol header
    Protocol *proto = (Protocol *)(frame + ETHER_ETHER_HEADER_LEN);
    EtherFillProtocol(proto, payload);

    // Payload
    uint8_t *payload_ptr = frame + ETHER_ETHER_HEADER_LEN + ETHER_PROTOCOL_LEN;
    memcpy(payload_ptr, payload.c_str(), payload.length());

    // Total frame length
    size_t frame_len = ETHER_ETHER_HEADER_LEN + ETHER_PROTOCOL_LEN + payload.length();
    SendFrame(handle, frame, frame_len);
}

// Simple checksum function
uint16_t checksum(uint16_t* data, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(uint8_t*)data;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

void SendIPPingPacket(pcap_t* handle, uint8_t frame[], std::string payload, uint8_t src_mac[], uint8_t dest_mac[], const char* src_ip, const char* dst_ip)
{
    // Ethernet header
    ether_header* eth = (ether_header*)frame;
    EtherFillEtherHeader(eth, src_mac, dest_mac, ETHERTYPE_IP);

    // IP header
    struct ip* iphdr = (struct ip*)(frame + ETHER_ETHER_HEADER_LEN);
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    iphdr->ip_len = htons(ETHER_IP_LEN + ETHER_ICMP_HEADER_LEN + payload.length());
    iphdr->ip_id = htons(1234);
    iphdr->ip_off = htons(IP_DF);
    iphdr->ip_ttl = 64;
    iphdr->ip_p = IPPROTO_ICMP;
    iphdr->ip_sum = 0;
    iphdr->ip_src.s_addr = inet_addr(src_ip);  // your IP
    iphdr->ip_dst.s_addr = inet_addr(dst_ip);    // target IP
    iphdr->ip_sum = checksum((uint16_t*)iphdr, ETHER_IP_LEN);

    // ICMP Echo Request
    struct icmphdr* icmp = (struct icmphdr*)(frame + ETHER_ETHER_HEADER_LEN + ETHER_IP_LEN);
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(0x1234);
    icmp->un.echo.sequence = htons(1);
    icmp->checksum = 0;

    // Payload
    uint8_t* payload_ptr = (uint8_t*)(icmp + 1);
    memcpy(payload_ptr, payload.c_str(), payload.length());

    // Calculate ICMP checksum (header + payload)
    int icmp_len = ETHER_ICMP_HEADER_LEN + payload.length();
    icmp->checksum = checksum((uint16_t*)icmp, icmp_len);

    int frame_len = ETHER_ETHER_HEADER_LEN + ETHER_IP_LEN + icmp_len;
    SendFrame(handle, frame, frame_len);
}

const char* program_name;
void usage()
{
    std::cout << "Error: Device is not provided.\n\n";
    std::cout << "Usage: " << program_name << " -d <device> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -mode <ip|raw>              Set transmission mode\n";
    std::cout << "  -n <number>                 Number of packets to send\n";
    exit(EXIT_FAILURE);
}

int main(int argc, char* argv[]) 
{
    int i = 0;
    program_name = argv[i];
    argc--; i++;
    const char* device = EtherInitDevices()->name;
    MODE mode = MODE::RAW_ETHER;
    int NumberOfPackets = 20;
    while (argc > 0)
    {
        if (strcmp(argv[i], "-d") == 0)
        {
            argc--; i++;
            if (argc >= 1)
            {
                device = argv[i];
                argc--; i++;
            }
            else
            {
                usage();
            }
        }
        else if (strcmp(argv[i], "-mode") == 0)
        {
            argc--; i++;
            if (argc >= 1)
            {
                if (strcmp(argv[i], "ip") == 0)
                    mode = MODE::IP;
                else if (strcmp(argv[i], "raw") == 0)
                    mode = MODE::RAW_ETHER;
                argc--; i++;
            }
            else
            {
                usage();
            }
        }
        else if (strcmp(argv[i], "-n") == 0)
        {
            argc--; i++;
            if (argc >= 1)
            {
                NumberOfPackets = std::stoi(argv[i]);
                argc--; i++;
            }   
            else
            {
                usage();
            }
        }
    }
    

    char errbuf[PCAP_ERRBUF_SIZE];
    // TODO: fix wireless interface to be able to send
    // const char *dev = "wlan0";  // Interface
    pcap_t *handle = EtherOpenDevice(NULL, device, errbuf, PROMISC::SEND);

    // using command: `ip address`, these are from interface eth0
    const char* src_ip = "172.30.160.245";
    uint8_t src_mac[ETHER_ADDR_LEN]  = {0x00, 0x15, 0x5d, 0x0c, 0xdb, 0x26};
    // from pinging the router's ip addresss `192.168.100.1` and running `arp -a 192.168.100.1` got the mac address
    const char* dst_ip = "192.168.100.1";
    // uint8_t dest_mac[ETHER_ADDR_LEN] = {0xd8, 0x76, 0xae, 0x51, 0x10, 0x44};
    uint8_t dest_mac[ETHER_ADDR_LEN] = {0x00, 0x15, 0x5d, 0x5d, 0xc8, 0x1a};


    uint8_t frame[ETHER_MAX_FRAME_LEN] = {0};

    for (int i = 0; i < NumberOfPackets; i++) {
        std::stringstream ss;
        ss << "Hello, Router! Packet #" << (i + 1);
        std::string payload = ss.str();
        if (mode == MODE::IP)
            SendIPPingPacket(handle, frame, payload, src_mac, dest_mac, src_ip, dst_ip);
        else if (mode == MODE::RAW_ETHER)
            SendRawPacket(handle, frame, payload, src_mac, dest_mac);

        memset(frame, 0, ETHER_MAX_FRAME_LEN);
    }

    printf("Packets sent!\n");
    pcap_close(handle);
    return 0;
}
