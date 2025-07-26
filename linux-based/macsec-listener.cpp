#include <iomanip>
#include <pcap.h>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <iostream>
#include <cstring>
#include <time.h>
#include <iomanip>

clock_t Clocker;
void StartClock()
{
    Clocker = clock();
}
double EvaluateClock(bool Verbose = false)
{
    clock_t t = clock() - Clocker;
    double TimeTaken = (double)(t) / CLOCKS_PER_SEC;
    if (Verbose)
    {
        std::cout << "Time taken (precision): " << std::fixed << std::setprecision(8) << TimeTaken << "s\n";
    }
    std::cout.unsetf(std::ios::fixed);
    std::cout.precision(6);
    return TimeTaken;
}

using namespace CryptoPP;

void print_hex(const uint8_t* data, size_t len, const char* label) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)data[i] << " ";
    std::cout << std::dec << std::endl;
}

void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    if (header->caplen < 30) return; // Minimum for MACsec frame

    const uint8_t* dst_mac = packet;
    const uint8_t* src_mac = packet + 6;
    const uint8_t* eth_type = packet + 12;

    uint16_t type = (eth_type[0] << 8) | eth_type[1];
    if (type != 0x88E5) return; // Not a MACsec frame

    std::cout << "\n== MACsec Frame Received ==" << std::endl;
    if (user)
    {
        std::cout << "User data: " << user << std::endl;
    }
    std::cout << "Packet Length: " << header->len << " bytes" << std::endl;
    std::cout << "Captured Length: " << header->caplen << " bytes" << std::endl;
    print_hex(dst_mac, 6, "Dest MAC");
    print_hex(src_mac, 6, "Src MAC");

    std::cout << "EtherType: 0x88E5 (MACsec)" << std::endl;

    const uint8_t* sectag = packet + 14;

    uint8_t tci = sectag[0];
    uint8_t an_sl = sectag[1];
    uint16_t pn = (sectag[2] << 8) | sectag[3];
    const uint8_t* sci = sectag + 4;

    std::cout << "TCI: 0x" << std::hex << (int)tci << std::endl;
    std::cout << "AN/SL: 0x" << std::hex << (int)an_sl << std::endl;
    std::cout << "Packet Number (PN): " << std::dec << pn << std::endl;

    std::cout << "SCI: ";
    for (int i = 0; i < 8; i++) {
        printf("%02X", sci[i]);
        if (i == 5) std::cout << "/";
    }
    std::cout << std::endl;

    size_t offset = 14 + 16; // 6+6+2 = Ethernet header, 12 = SecTAG+SCI
    size_t encrypted_len = header->caplen - offset;
    if (encrypted_len < 16) {
        std::cout << "Frame too short for ICV.\n";
        return;
    }

    size_t payload_len = encrypted_len - 16;
    const uint8_t* payload = packet + offset;
    const uint8_t* icv = packet + offset + payload_len;

    print_hex(payload, payload_len, "Encrypted Payload");
    std::cout << "Payload Length: " << payload_len << " bytes" << std::endl;
    // deycrypt the payload
    try 
    {
        uint8_t key[16] = {
            0x8F, 0x7D, 0x5F, 0x7B, 0xB2, 0x86, 0xE7, 0x39,
            0x73, 0x3A, 0x92, 0x0E, 0x7F, 0x91, 0xED, 0x95
        };
        uint8_t iv[12] = {0};
        memcpy(iv, sectag + 4, 12);

        GCM<AES>::Decryption dec;
        dec.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
        std::string decrypted;
        AuthenticatedDecryptionFilter df(dec,
            new StringSink(decrypted),
            AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            16 // MAC size
        );

        df.ChannelPut(AAD_CHANNEL, sectag, 16);          // AAD = SecTAG (4) + SCI (8) = 12–16 bytes
        df.ChannelMessageEnd(AAD_CHANNEL);               // must come before any payload
        df.ChannelPut(DEFAULT_CHANNEL, payload, payload_len + 16);
        df.ChannelMessageEnd(DEFAULT_CHANNEL);

        std::cout << "Decrypted Payload: ";
        std::cout << decrypted << std::endl;

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Decryption failed: " << e.what() << std::endl;
    }

    print_hex(icv, 16, "ICV/TAG");

    std::cout << "=============================\n";
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* dev = "eth0";  // Change this to your network interface

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Listening for MACsec frames on interface: " << dev << "\n";
    pcap_loop(handle, 0, packet_handler, nullptr);

    pcap_close(handle);
    return 0;
}
