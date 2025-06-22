#include <iostream>
#include <sstream>
#include <vector>
#include "ether.h"

const char* program_name = NULL;
const char* device = NULL;
MODE mode = (MODE)0;
int NumberOfPackets = 0;
const char* SourceIP = NULL;
const char* DestinationIP = NULL;
uint8_t SourceMAC[ETHER_ADDR_LEN]  = {0};
uint8_t DestinationMAC[ETHER_ADDR_LEN] = {0};

void EtherFillARPHeader(uint8_t* arp, uint8_t SourceMAC[], uint8_t SourceIP_bin[], uint8_t DestinationIP_bin[])
{
    arp[0]  = 0x00; arp[1]  = 0x01;        // Hardware type: Ethernet
    arp[2]  = 0x08; arp[3]  = 0x00;        // Protocol type: IPv4
    arp[4]  = 0x06;                        // Hardware size: 6
    arp[5]  = 0x04;                        // Protocol size: 4
    arp[6]  = 0x00; arp[7]  = 0x01;        // Opcode: request

    memcpy(arp + 8,  SourceMAC,     6);      // Sender MAC
    memcpy(arp + 14, SourceIP_bin,  4);      // Sender IP
    memset(arp + 18, 0x00,        6);      // Target MAC (unknown)
    memcpy(arp + 24, DestinationIP_bin,  4);      // Target IP
}

void SendARPPacket(pcap_t* handle, uint8_t frame[]) {
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t SourceIP_bin[4], DestinationIP_bin[4];

    inet_pton(AF_INET, SourceIP, SourceIP_bin);
    inet_pton(AF_INET, DestinationIP, DestinationIP_bin);

    memset(frame, 0, 42);

    ether_header* eth = (ether_header*)frame;
    EtherFillEtherHeader(eth, SourceMAC, broadcast_mac, ETHERTYPE_ARP);

    // ARP header
    EtherFillARPHeader(frame + 14, SourceMAC, SourceIP_bin, DestinationIP_bin);

    // Send the packet
    EtherSendFrame(handle, frame, 42);
}

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

void EtherFillIPHeader(ip* iphdr, uint8_t IPProtocol, std::string payload)
{
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    iphdr->ip_len = htons(ETHER_IP_LEN + ETHER_ICMP_HEADER_LEN + payload.length());
    iphdr->ip_id = htons(1234);
    iphdr->ip_off = htons(IP_DF);
    iphdr->ip_ttl = 64;
    iphdr->ip_p = IPProtocol;
    iphdr->ip_sum = 0;
    iphdr->ip_src.s_addr = inet_addr(SourceIP);  // your IP
    iphdr->ip_dst.s_addr = inet_addr(DestinationIP);    // target IP
    iphdr->ip_sum = checksum((uint16_t*)iphdr, ETHER_IP_LEN);
}

void EtherFillICMPHeader(icmphdr* icmp, uint8_t ICMPType)
{
    icmp->type = ICMPType;
    icmp->code = 0;
    icmp->un.echo.id = htons(0x1234);
    icmp->un.echo.sequence = htons(1);
    icmp->checksum = 0;
}

void SendIPPingPacket(pcap_t* handle, uint8_t frame[], std::string payload)
{
    ether_header* eth = (ether_header*)frame;
    EtherFillEtherHeader(eth, SourceMAC, DestinationMAC, ETHERTYPE_IP);

    struct ip* iphdr = (struct ip*)(frame + ETHER_ETHER_HEADER_LEN);
    EtherFillIPHeader(iphdr, IPPROTO_ICMP, payload);

    struct icmphdr* icmp = (struct icmphdr*)(frame + ETHER_ETHER_HEADER_LEN + ETHER_IP_LEN);
    EtherFillICMPHeader(icmp, ICMP_ECHO);

    // Payload
    uint8_t* payload_ptr = (uint8_t*)(icmp + 1);
    memcpy(payload_ptr, payload.c_str(), payload.length());

    // Calculate ICMP checksum (header + payload)
    int icmp_len = ETHER_ICMP_HEADER_LEN + payload.length();
    icmp->checksum = checksum((uint16_t*)icmp, icmp_len);

    int frame_len = ETHER_ETHER_HEADER_LEN + ETHER_IP_LEN + icmp_len;
    EtherSendFrame(handle, frame, frame_len);
}

std::vector<uint8_t> HexStringToByteArray(const std::string& hexStr) {
    std::string hex = hexStr;

    // Remove "0x" or "0X" prefix if present
    if (hex.substr(0, 2) == "0x" || hex.substr(0, 2) == "0X") {
        hex = hex.substr(2);
    }

    // Make sure string has even length
    if (hex.length() % 2 != 0) {
        hex = "0" + hex;  // Pad with leading zero
    }

    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

void usage()
{
    std::cout << "Error: Device is not provided.\n\n";
    std::cout << "Usage: " << program_name << " -d <device> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -mode <echo|arpreq>         Set transmission mode\n";
    std::cout << "  -sip <ip address>           source ip address\n";
    std::cout << "  -dip <ip address>           destination ip address\n";
    std::cout << "  -smac <mac address in hex>  source mac address\n";
    std::cout << "  -dmac <mac address in hex>  destination mac address\n";
    std::cout << "  -n <number>                 Number of packets to send\n";
    std::cout << "example: " << program_name << " -d eth0 -mode echo -sip 192.168.10.10 -dip 192.168.20.20 -smac 0x112233445566 -dmac 0x112233445566 -n 10\n";
    exit(EXIT_FAILURE);
}

void ParseCommandLineArgs(int argc, char* argv[]);

int main(int argc, char* argv[]) 
{
    ParseCommandLineArgs(argc, argv);
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = EtherOpenDevice(NULL, device, errbuf, PROMISC::SEND);
    uint8_t frame[ETHER_MAX_FRAME_LEN] = {0};

    if (mode == MODE::ARP_REQUEST)
    {
        for (int i = 0; i < NumberOfPackets; i++)
        {
            SendARPPacket(handle, frame);
            memset(frame, 0, ETHER_MAX_FRAME_LEN);
        }
    }
    else if (mode == MODE::IP_ICMP_ECHO)
    {
        for (int i = 0; i < NumberOfPackets; i++) {
            std::stringstream ss;
            ss << "Hello, Router! Packet #" << (i + 1);
            std::string payload = ss.str();
            SendIPPingPacket(handle, frame, payload);
            memset(frame, 0, ETHER_MAX_FRAME_LEN);
        }
    }
    printf("Packets sent!\n");

    pcap_close(handle);
    return 0;
}


void ParseCommandLineArgs(int argc, char* argv[])
{
    int i = 0;
    program_name = argv[i];
    argc--; i++;
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
                if (strcmp(argv[i], "echo") == 0)
                    mode = MODE::IP_ICMP_ECHO;
                else if (strcmp(argv[i], "arpreq") == 0)
                    mode = MODE::ARP_REQUEST;
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
        else if (strcmp(argv[i], "-sip") == 0)
        {
            argc--; i++;
            if (argc >= 1)
            {
                SourceIP = argv[i];
                argc--; i++;
            }
            else
            {
                usage();
            }
        }
        else if (strcmp(argv[i], "-dip") == 0)
        {
            argc--; i++;
            if (argc >= 1)
            {
                DestinationIP = argv[i];
                argc--; i++;
            }
            else
            {
                usage();
            }
        }
        else if (strcmp(argv[i], "-smac") == 0)
        {
            argc--; i++;
            if (argc >= 1)
            {
                const char* MAC_text = argv[i];
                memcpy(SourceMAC, HexStringToByteArray(MAC_text).data(), ETHER_ADDR_LEN);
                argc--; i++;
            }
            else
            {
                usage();
            }
        }
        else if (strcmp(argv[i], "-dmac") == 0)
        {
            argc--; i++;
            if (argc >= 1)
            {
                const char* MAC_text = argv[i];
                memcpy(DestinationMAC, HexStringToByteArray(MAC_text).data(), ETHER_ADDR_LEN);
                argc--; i++;
            }
            else
            {
                usage();
            }
        }
    }
}