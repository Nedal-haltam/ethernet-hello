#include <iostream>
#include <sstream>
#include <crypto++/aes.h>
#include <crypto++/gcm.h>
#include <crypto++/osrng.h>
#include <crypto++/filters.h>
#include <crypto++/secblock.h>
#include "ether.h"

using namespace CryptoPP;

typedef struct 
{
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
    bool MACSEC_AES_GCM_ENCRYPT = false;
} Config;

Config config = {0};



void SendARPPacket(pcap_t* handle, uint8_t frame[]) {
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t SourceIP_bin[4], DestinationIP_bin[4];

    inet_pton(AF_INET, config.SourceIP, SourceIP_bin);
    inet_pton(AF_INET, config.DestinationIP, DestinationIP_bin);

    memset(frame, 0, 42);

    ether_header* eth = (ether_header*)frame;
    EtherFillEtherHeader(eth, config.SourceMAC, broadcast_mac, ETHERTYPE_ARP);

    EtherFillARPHeader(frame + 14, config.SourceMAC, SourceIP_bin, DestinationIP_bin);

    EtherSendFrame(handle, frame, 42);
}

void SendIPPingPacket(pcap_t* handle, uint8_t frame[], std::string payload)
{
    ether_header* eth = (ether_header*)frame;
    EtherFillEtherHeader(eth, config.SourceMAC, config.DestinationMAC, ETHERTYPE_IP);

    struct ip* iphdr = (struct ip*)(frame + ETHER_ETHER_HEADER_LEN);
    EtherFillIPHeader(iphdr, IPPROTO_ICMP, payload.length(), config.SourceIP, config.DestinationIP);

    struct icmphdr* icmp = (struct icmphdr*)(frame + ETHER_ETHER_HEADER_LEN + ETHER_IP_LEN);
    EtherFillICMPHeader(icmp, ICMP_ECHO);

    uint8_t* payload_ptr = (uint8_t*)(icmp + 1);
    memcpy(payload_ptr, payload.c_str(), payload.length());

    int icmp_len = ETHER_ICMP_HEADER_LEN + payload.length();
    icmp->checksum = checksum((uint16_t*)icmp, icmp_len);

    int frame_len = ETHER_ETHER_HEADER_LEN + ETHER_IP_LEN + icmp_len;
    EtherSendFrame(handle, frame, frame_len);
}

void usage();
void ParseCommandLineArgs(int argc, char* argv[]);

bool IsValidArgs()
{
    if (config.mode == MODE::INVALID || !config.GOT_device) return false;

    if (config.mode == MODE::IP_ICMP_ECHO)
    {
        return config.GOT_SourceIP && config.GOT_DestinationIP && config.GOT_SourceMAC && config.GOT_DestinationMAC;
    }
    else if (config.mode == MODE::ARP_REQUEST)
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
    pcap_t *handle = EtherOpenDevice(NULL, config.device, errbuf, PROMISC::SEND);
    uint8_t frame[ETHER_MAX_FRAME_LEN] = {0};

    if (config.mode == MODE::ARP_REQUEST)
    {
        for (int i = 0; i < config.NumberOfPackets; i++)
        {
            SendARPPacket(handle, frame);
            memset(frame, 0, ETHER_MAX_FRAME_LEN);
        }
        printf("Packets sent!\n");
    }
    else if (config.mode == MODE::IP_ICMP_ECHO)
    {
        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        byte iv[IV_LEN];
        std::string aad;
        if (config.MACSEC_AES_GCM_ENCRYPT)
        {
            load(key, iv, aad, "key_iv_aad.bin");
        }
        for (int i = 0; i < config.NumberOfPackets; i++) {
            // TODO: change payload to uint8_t[]
            std::string payload;
            std::stringstream ss;
            ss << "Hello, Router! Packet #" << (i + 1);
            std::string plain = ss.str();
            if (config.MACSEC_AES_GCM_ENCRYPT)
            {
                // if MACSEC_AES_GCM_ENCRYPT flag was raised
                // ciphertext = encrypt(payload)
                // payload = [IV (12 bytes)] [ciphertext + tag (TAG_LEN bytes)]
                std::string cipher = encrypt(plain, key, iv, aad);
                std::string IV(reinterpret_cast<const char*>(iv), IV_LEN);
                payload = ETHER_MAGIC_MACSEC_WORD + IV + cipher;
            }
            else
            {
                payload = plain;
            }
            SendIPPingPacket(handle, frame, payload);
            memset(frame, 0, ETHER_MAX_FRAME_LEN);
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
                    config.mode = MODE::IP_ICMP_ECHO;
                }
                else if (strcmp(argv[i], "arpreq") == 0)
                {
                    config.mode = MODE::ARP_REQUEST;
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
                memcpy(config.SourceMAC, HexStringToByteArray(MAC_text).data(), ETHER_ADDR_LEN);
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
                memcpy(config.DestinationMAC, HexStringToByteArray(MAC_text).data(), ETHER_ADDR_LEN);
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