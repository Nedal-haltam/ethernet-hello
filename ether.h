#pragma once

#include <iostream>
#include <vector>
#include <pcap.h>
#include <netinet/udp.h>  
#include <netinet/ip.h>   
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <cstring>
#include <netinet/ip_icmp.h>

#include <iomanip>
#include <crypto++/aes.h>
#include <crypto++/gcm.h>
#include <crypto++/osrng.h>
#include <crypto++/filters.h>
#include <crypto++/secblock.h>
#include <fstream>

using namespace CryptoPP;

#define CallBackType(VariableName) void (*VariableName)(u_char *, const pcap_pkthdr *, const u_char *)

#define ETHER_ETHER_HEADER_LEN (sizeof(ether_header))
#define ETHER_IP_LEN (sizeof(struct ip))
#define ETHER_UDP_HEADER_LEN (sizeof(struct udphdr))
#define ETHER_ICMP_HEADER_LEN (sizeof(struct icmphdr))
#define ETHER_PAYLOAD_LEN (1500)
#define ETHER_MAX_FRAME_LEN (ETHER_ETHER_HEADER_LEN + ETHER_PAYLOAD_LEN)
#define ETHER_COSTUME_ETHER_TYPE (0x88B5)

#define ETHER_MAGIC_MACSEC_WORD "MAGICMACSEC"
#define TAG_LEN 16
#define IV_LEN 12

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
    SEND, RECEIVE
};

enum MODE
{
    INVALID,
    IP_ICMP_ECHO,
    ARP_REQUEST,
};


std::vector<uint8_t> HexStringToByteArray(const std::string& hexStr) {
    std::string hex = hexStr;

    
    if (hex.substr(0, 2) == "0x" || hex.substr(0, 2) == "0X") {
        hex = hex.substr(2);
    }

    
    if (hex.length() % 2 != 0) {
        hex = "0" + hex;  
    }

    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
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

void EtherFillEtherHeader(ether_header *eth, uint8_t src_mac[], uint8_t dest_mac[], uint16_t ether_type)
{
    memcpy(eth->ether_dhost, dest_mac, ETHER_ADDR_LEN);
    memcpy(eth->ether_shost, src_mac, ETHER_ADDR_LEN);
    eth->ether_type = htons(ether_type);
}

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

void EtherFillIPHeader(ip* iphdr, uint8_t IPProtocol, size_t payload_len, const char* SourceIP, const char* DestinationIP)
{
    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;
    iphdr->ip_len = htons(ETHER_IP_LEN + ETHER_ICMP_HEADER_LEN + payload_len);
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

    int payload_len = header->len - ETHER_ETHER_HEADER_LEN;
    std::cout << "  Payload (" << payload_len << " bytes): ";
    const u_char* payload = packet + ETHER_ETHER_HEADER_LEN;
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

void EtherSendFrame(pcap_t * handle, uint8_t frame[], size_t frame_len)
{
    // the `pcap_sendpacket` function or the NIC card sets the (Preamble, SFD, and FCS)
    if (pcap_sendpacket(handle, frame, frame_len) != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
}


std::string encrypt(std::string plain, SecByteBlock key, byte iv[IV_LEN], std::string aad)
{
    std::string cipher;
    try {
        GCM<AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), iv, IV_LEN * sizeof(byte));

        AuthenticatedEncryptionFilter ef(enc, new StringSink(cipher), false, TAG_LEN);

        ef.ChannelPut("AAD", reinterpret_cast<const byte*>(aad.data()), aad.length());
        ef.ChannelMessageEnd("AAD");

        ef.ChannelPut("", reinterpret_cast<const byte*>(plain.data()), plain.length());
        ef.ChannelMessageEnd("");
    } catch (const Exception& e) {
        std::cerr << "Encryption error: " << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    return cipher;
}

std::string decrypt(std::string cipher, SecByteBlock key, byte iv[IV_LEN], std::string aad)
{
    std::string recovered;
    try 
    {
        GCM<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv, IV_LEN * sizeof(byte));

        AuthenticatedDecryptionFilter df(dec, new StringSink(recovered), AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_LEN);

        df.ChannelPut("AAD", (const byte*)aad.data(), aad.size());
        df.ChannelMessageEnd("AAD");

        df.ChannelPut("", (const byte*)cipher.data(), cipher.size());
        df.ChannelMessageEnd("");
    } 
    catch (const Exception& e) 
    {
        std::cerr << "Decryption failed: " << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    return recovered;
}

void PrintInfoString(std::string data, std::string name)
{
    std::cout << name << " length: `" << data.length() << "`" << std::endl;
    std::cout << name << ":";
    for (int i = 0; i < (int)data.length(); i++)
    {
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << (static_cast<unsigned int>(static_cast<unsigned char>(data[i]))) << " ";
    }
    std::cout << std::dec << std::nouppercase << std::setfill(' ');
    std::cout << std::endl;
    std::cout << name << ": " << "`" << data << "`" << std::endl;
}

void encrypt_decrypt_and_print(SecByteBlock& key, byte iv[IV_LEN], std::string& aad)
{
    std::string payload = "abcdefghij";
    std::string cipher = encrypt(payload, key, iv, aad);
    std::string recovered = decrypt(cipher, key, iv, aad);

    PrintInfoString(payload, "Payload");
    std::cout << "---------------------------------------------------------" << std::endl;
    PrintInfoString(cipher, "Cipher");
    std::cout << "---------------------------------------------------------" << std::endl;
    PrintInfoString(recovered, "Recovered");
}

void save(SecByteBlock& key, byte iv[IV_LEN], std::string& aad, const char* FilePath)
{
    std::ofstream out(FilePath, std::ios::binary);
    if (!out) {
        std::cerr << "❌ Failed to open file for writing key, IV, and AAD." << std::endl;
        exit(EXIT_FAILURE);
    }

    // Write key
    out.write(reinterpret_cast<const char*>(key.data()), key.SizeInBytes());

    // Write IV
    out.write(reinterpret_cast<const char*>(iv), IV_LEN);

    uint32_t aad_len = static_cast<uint32_t>(aad.size());
    out.write(reinterpret_cast<const char*>(&aad_len), sizeof(aad_len));
    out.write(aad.data(), aad_len);

    out.close();
    std::cout << "✅ Key, IV, and AAD saved successfully.\n";
}

void load(SecByteBlock& key, byte iv[IV_LEN], std::string& aad, const char* FilePath) {
    std::ifstream in(FilePath, std::ios::binary);
    if (!in) {
        std::cerr << "❌ Failed to open file for reading key, IV, and AAD." << std::endl;
        exit(EXIT_FAILURE);
    }

    // Read key
    in.read(reinterpret_cast<char*>(key.data()), key.size());

    // Read IV
    in.read(reinterpret_cast<char*>(iv), IV_LEN);

    // Read AAD length and content
    uint32_t aad_len = 0;
    in.read(reinterpret_cast<char*>(&aad_len), sizeof(aad_len));
    aad.resize(aad_len);
    in.read(&aad[0], aad_len);

    in.close();
    std::cout << "✅ Key, IV, and AAD loaded successfully.\n";
}

void Printkeyivaad(SecByteBlock& key, byte iv[IV_LEN], std::string& aad)
{
    std::cout << "key: " << key.data() << std::endl;
    std::cout << "key len: " << key.size() << std::endl;
    std::cout << "iv: ";
    for (int i = 0; i < IV_LEN; i++)
        std::cout << iv[i];
    std::cout << std::endl;
    std::cout << "aad: " << aad << std::endl;
}

void save_and_print(SecByteBlock& key, byte iv[IV_LEN], std::string& aad)
{
    save(key, iv, aad, "key_iv_aad.bin");
    Printkeyivaad(key, iv, aad);
}

void load_and_print(SecByteBlock& key, byte iv[IV_LEN], std::string& aad)
{
    load(key, iv, aad, "key_iv_aad.bin");
    Printkeyivaad(key, iv, aad);
}
