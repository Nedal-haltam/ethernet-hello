#include <iostream>
#include <sstream>
#include "ether.h"

const char* program_name = NULL;
MODE mode = MODE::INVALID;
int NumberOfPackets = 0;

const char* device = NULL;
const char* SourceIP = NULL;
const char* DestinationIP = NULL;
uint8_t SourceMAC[ETHER_ADDR_LEN]  = {0};
uint8_t DestinationMAC[ETHER_ADDR_LEN] = {0};
bool GOT_device = false;
bool GOT_SourceIP = false;
bool GOT_DestinationIP = false;
bool GOT_SourceMAC = false;
bool GOT_DestinationMAC = false;

void SendARPPacket(pcap_t* handle, uint8_t frame[]) {
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t SourceIP_bin[4], DestinationIP_bin[4];

    inet_pton(AF_INET, SourceIP, SourceIP_bin);
    inet_pton(AF_INET, DestinationIP, DestinationIP_bin);

    memset(frame, 0, 42);

    ether_header* eth = (ether_header*)frame;
    EtherFillEtherHeader(eth, SourceMAC, broadcast_mac, ETHERTYPE_ARP);

    EtherFillARPHeader(frame + 14, SourceMAC, SourceIP_bin, DestinationIP_bin);

    EtherSendFrame(handle, frame, 42);
}

void SendIPPingPacket(pcap_t* handle, uint8_t frame[], std::string payload)
{
    ether_header* eth = (ether_header*)frame;
    EtherFillEtherHeader(eth, SourceMAC, DestinationMAC, ETHERTYPE_IP);

    struct ip* iphdr = (struct ip*)(frame + ETHER_ETHER_HEADER_LEN);
    EtherFillIPHeader(iphdr, IPPROTO_ICMP, payload, SourceIP, DestinationIP);

    struct icmphdr* icmp = (struct icmphdr*)(frame + ETHER_ETHER_HEADER_LEN + ETHER_IP_LEN);
    EtherFillICMPHeader(icmp, ICMP_ECHO);

    uint8_t* payload_ptr = (uint8_t*)(icmp + 1);
    memcpy(payload_ptr, payload.c_str(), payload.length());

    int icmp_len = ETHER_ICMP_HEADER_LEN + payload.length();
    icmp->checksum = checksum((uint16_t*)icmp, icmp_len);

    int frame_len = ETHER_ETHER_HEADER_LEN + ETHER_IP_LEN + icmp_len;
    EtherSendFrame(handle, frame, frame_len);
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
    std::cout << "example: " << program_name << " -d eth0 -mode echo -sip 192.168.10.10 -dip 192.168.20.20 -smac 0x112233445566 -dmac 0x112233445566 -n 10\n\n";
    exit(EXIT_FAILURE);
}

void ParseCommandLineArgs(int argc, char* argv[]);

bool IsValidArgs()
{
    if (mode == MODE::INVALID || !GOT_device) return false;

    if (mode == MODE::IP_ICMP_ECHO)
    {
        return GOT_SourceIP && GOT_DestinationIP && GOT_SourceMAC && GOT_DestinationMAC;
    }
    else if (mode == MODE::ARP_REQUEST)
    {
        return GOT_SourceIP && GOT_DestinationIP && GOT_SourceMAC; 
    }
    return false;
}

int main(int argc, char* argv[]) 
{
    ParseCommandLineArgs(argc, argv);
    if (!IsValidArgs()) return EXIT_FAILURE;
    
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
        printf("Packets sent!\n");
    }
    else if (mode == MODE::IP_ICMP_ECHO)
    {
        for (int i = 0; i < NumberOfPackets; i++) {
            // TODO: change payload to uint8_t[]
            std::stringstream ss;
            ss << "Hello, Router! Packet #" << (i + 1);
            std::string payload = ss.str();
            SendIPPingPacket(handle, frame, payload);
            memset(frame, 0, ETHER_MAX_FRAME_LEN);
        }
        printf("Packets sent!\n");
    }

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
                GOT_device = true;
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
                GOT_SourceIP = true;
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
                GOT_DestinationIP = true;
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
                GOT_SourceMAC = true;
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
                GOT_DestinationMAC = true;
            }
            else
            {
                usage();
            }
        }
        else
        {
            usage();
        }
    }
}