#include <iostream>
#include <sstream>
#include "ether.h"


void SendFrame(pcap_t * handle, uint8_t frame[], size_t frame_len)
{
    // the `pcap_sendpacket` function or the NIC card sets the (Preamble, SFD, and FCS)
    if (pcap_sendpacket(handle, frame, frame_len) != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
}

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
    SendFrame(handle, frame, frame_len);
}

#define ETHER_TYPE_IP 0x0800
void SendIPPacket(pcap_t* handle, uint8_t frame[], std::string payload, uint8_t src_mac[], uint8_t dest_mac[], const char* src_ip, const char* dst_ip)
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
    ip->ip_src.s_addr = inet_addr(src_ip);
    ip->ip_dst.s_addr = inet_addr(dst_ip);

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
    SendFrame(handle, frame, frame_len);
}

const char* program_name;
void usage()
{
    std::cout << "device is not provided\n";
    std::cout << "Usage: " << program_name << " -d <device> [options]\n";
    std::cout << "Options:\n";
    std::cout << "    -mode <ip|raw>\n";
    std::cout << "    -n <number of packets to send>\n";
    exit(EXIT_FAILURE);
}

int main(int argc, char* argv[]) 
{
    int i = 0;
    program_name = argv[i];
    argc--; i++;
    const char* device = NULL;
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
    if (!device)
    {
        usage();
    }
    

    char errbuf[PCAP_ERRBUF_SIZE];
    // TODO: fix wireless interface to be able to send
    // const char *dev = "wlan0";  // Interface
    pcap_t *handle = EtherOpenDevice(NULL, device, errbuf, PROMISC::SEND);


    uint8_t src_mac[ETHER_ADDR_LEN]  = {0x00, 0x15, 0x5D, 0x5D, 0xC8, 0x1A};
    uint8_t dest_mac[ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const char* src_ip = "192.168.1.10";
    const char* dst_ip = "192.168.1.5";

    uint8_t frame[ETHER_MAX_FRAME_LEN] = {0};

    for (int i = 0; i < NumberOfPackets; i++) {
        std::stringstream ss;
        ss << "Hello, Router! Packet #" << (i + 1);
        std::string payload = ss.str();
        if (mode == MODE::IP)
            SendIPPacket(handle, frame, payload, src_mac, dest_mac, src_ip, dst_ip);
        else if (mode == MODE::RAW_ETHER)
            SendRawPacket(handle, frame, payload, src_mac, dest_mac);

        memset(frame, 0, ETHER_MAX_FRAME_LEN);
    }

    printf("Packets sent!\n");
    pcap_close(handle);
    return 0;
}
