#include <iostream>
#include <sstream>
#include "ether.h"

using namespace CryptoPP;

typedef struct 
{
    const char* program_name;
    ether::MODE mode;
    int NumberOfPackets;

    const char* device;
    const char* SourceIP;
    const char* DestinationIP;
    uint8_t SourceMAC[ETHER_ADDR_LEN] ;
    uint8_t DestinationMAC[ETHER_ADDR_LEN];
    bool GOT_device;
    bool GOT_SourceIP;
    bool GOT_DestinationIP;
    bool GOT_SourceMAC;
    bool GOT_DestinationMAC;
    bool MACSEC_AES_GCM_ENCRYPT;
} Config;

Config config;



void SendARPPacket(pcap_t* handle, uint8_t frame[]) {
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t SourceIP_bin[4], DestinationIP_bin[4];

    inet_pton(AF_INET, config.SourceIP, SourceIP_bin);
    inet_pton(AF_INET, config.DestinationIP, DestinationIP_bin);

    memset(frame, 0, 42);

    ether_header* eth = (ether_header*)frame;
    ether::FillEtherHeader(eth, config.SourceMAC, broadcast_mac, ETHERTYPE_ARP);

    ether::FillARPHeader(frame + 14, config.SourceMAC, SourceIP_bin, DestinationIP_bin);

    ether::SendFrame(handle, frame, 42);
}

void SendIPPingPacket(pcap_t* handle, uint8_t frame[], std::string payload)
{
    ether_header* eth = (ether_header*)frame;
    ether::FillEtherHeader(eth, config.SourceMAC, config.DestinationMAC, ETHERTYPE_IP);

    struct ip* iphdr = (struct ip*)(frame + ETHER_HEADER_LEN);
    ether::FillIPHeader(iphdr, IPPROTO_ICMP, payload.length(), config.SourceIP, config.DestinationIP);

    struct icmphdr* icmp = (struct icmphdr*)(frame + ETHER_HEADER_LEN + IP_LEN);
    ether::FillICMPHeader(icmp, ICMP_ECHO);

    uint8_t* payload_ptr = (uint8_t*)(icmp + 1);
    memcpy(payload_ptr, payload.c_str(), payload.length());

    int icmp_len = ICMP_HEADER_LEN + payload.length();
    icmp->checksum = ether::checksum((uint16_t*)icmp, icmp_len);

    int frame_len = ETHER_HEADER_LEN + IP_LEN + icmp_len;
    ether::SendFrame(handle, frame, frame_len);
}

void usage();
void ParseCommandLineArgs(int argc, char* argv[]);

bool IsValidArgs()
{
    if (!config.GOT_device) return false;

    if (config.mode == ether::MODE::IP_ICMP_ECHO)
    {
        return config.GOT_SourceIP && config.GOT_DestinationIP && config.GOT_SourceMAC && config.GOT_DestinationMAC;
    }
    else if (config.mode == ether::MODE::ARP_REQUEST)
    {
        return config.GOT_SourceIP && config.GOT_DestinationIP && config.GOT_SourceMAC; 
    }
    return false;
}

int main(int argc, char* argv[]) 
{
    ParseCommandLineArgs(argc, argv);
    if (!IsValidArgs()) 
        usage();
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = ether::OpenDevice(NULL, config.device, errbuf, ether::PROMISC::SEND);
    uint8_t frame[MAX_FRAME_LEN] = {0};

    if (config.mode == ether::MODE::ARP_REQUEST)
    {
        for (int i = 0; i < config.NumberOfPackets; i++)
        {
            SendARPPacket(handle, frame);
            memset(frame, 0, MAX_FRAME_LEN);
        }
        printf("Packets sent!\n");
    }
    else if (config.mode == ether::MODE::IP_ICMP_ECHO)
    {
        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        byte iv[IV_LEN];
        std::string aad;
        if (config.MACSEC_AES_GCM_ENCRYPT)
        {
            ether::load(key, iv, aad, "key_iv_aad.bin");
        }
        for (int i = 0; i < config.NumberOfPackets; i++) {
            std::string payload;
            std::stringstream ss;
            ss << "Hello, Router! Packet #" << (i + 1);
            std::string plain = ss.str();
            if (config.MACSEC_AES_GCM_ENCRYPT)
            {
                // if MACSEC_AES_GCM_ENCRYPT flag was raised
                // ciphertext = encrypt(payload)
                // payload = [IV (12 bytes)] [ciphertext + tag (TAG_LEN bytes)]
                std::string cipher = ether::encrypt(plain, key, iv, (unsigned char*)aad.data());
                std::string IV(reinterpret_cast<const char*>(iv), IV_LEN);
                payload = MAGIC_MACSEC_WORD + IV + cipher; // -> tag is in cipher
            }
            else
            {
                payload = plain;
            }
            SendIPPingPacket(handle, frame, payload);
            memset(frame, 0, MAX_FRAME_LEN);
        }
        printf("Packets sent!\n");
    }

    pcap_close(handle);
    return 0;
}

void usage()
{
    std::cout << "Error: Device is not provided.\n" << std::endl;
    std::cout << "Usage: " << config.program_name << " -d <device> [options]\n" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -mode <echo|arpreq>         Set transmission mode" << std::endl;
    std::cout << "  -sip <ip address>           source ip address" << std::endl;
    std::cout << "  -dip <ip address>           destination ip address" << std::endl;
    std::cout << "  -smac <mac address in hex>  source mac address" << std::endl;
    std::cout << "  -dmac <mac address in hex>  destination mac address" << std::endl;
    std::cout << "  -n <number>                 Number of packets to send" << std::endl;
    std::cout << "  -macsec                     enable payload encryption using AES-GCM scheme" << std::endl;
    std::cout << "                              default is disabled" << std::endl;

    std::cout << "example: " << config.program_name << " -d eth0 -mode echo -sip 192.168.10.10 -dip 192.168.20.20 -smac 0x112233445566 -dmac 0x112233445566 -n 10\n" << std::endl;
    exit(EXIT_FAILURE);
}

void ParseCommandLineArgs(int argc, char* argv[])
{
    int i = 0;
    config.program_name = argv[i];
    argc--; i++;
    while (argc > 0)
    {
        if (strcmp(argv[i], "-d") == 0)
        {
            argc--; i++;
            if (argc >= 1)
            {
                config.device = argv[i];
                argc--; i++;
                config.GOT_device = true;
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
                {
                    config.mode = ether::MODE::IP_ICMP_ECHO;
                }
                else if (strcmp(argv[i], "arpreq") == 0)
                {
                    config.mode = ether::MODE::ARP_REQUEST;
                }
                else
                {
                    usage();
                }
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
                config.NumberOfPackets = std::stoi(argv[i]);
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
                config.SourceIP = argv[i];
                argc--; i++;
                config.GOT_SourceIP = true;
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
                config.DestinationIP = argv[i];
                argc--; i++;
                config.GOT_DestinationIP = true;
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
                memcpy(config.SourceMAC, ether::HexStringToByteArray(MAC_text).data(), ETHER_ADDR_LEN);
                argc--; i++;
                config.GOT_SourceMAC = true;
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
                memcpy(config.DestinationMAC, ether::HexStringToByteArray(MAC_text).data(), ETHER_ADDR_LEN);
                argc--; i++;
                config.GOT_DestinationMAC = true;
            }
            else
            {
                usage();
            }
        }
        else if (strcmp(argv[i], "-macsec") == 0)
        {
            argc--; i++;
            config.MACSEC_AES_GCM_ENCRYPT = true;
        }
        else
        {
            usage();
        }
    }
}