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

#define ETHER_TYPE_MACSEC 0x88E5

std::string Encrypt(uint8_t* key, uint8_t* iv, const std::string& plaintext, uint8_t* aad)
{
    GCM<AES>::Encryption gcm;
    // gcm.SetKeyWithIV(key, key.size(), iv, sizeof(iv));
    gcm.SetKeyWithIV(key, 16, iv, 12);

    std::string ciphertext;

    AuthenticatedEncryptionFilter ef(gcm,
        new StringSink(ciphertext), false, 16 // tag size
    );
    ef.ChannelPut(AAD_CHANNEL, aad, 16);
    ef.ChannelMessageEnd(AAD_CHANNEL);

    ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(), plaintext.size());
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);
    return ciphertext;
}

int main() {
    AutoSeededRandomPool prng;
    const char* dev = "eth0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return 1;
    }



    uint8_t key[16] = {
        0x8F, 0x7D, 0x5F, 0x7B, 0xB2, 0x86, 0xE7, 0x39, 0x73, 0x3A, 0x92, 0x0E, 0x7F, 0x91, 0xED, 0x95
    };
    // SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    // prng.GenerateBlock(key, key.size());
    uint8_t iv[12] = {0};
    // Construct AAD (MACsec SecTAG + SCI (optional) = 16 bytes)
    // uint8_t iv[12] = {
    //     0xE8, 0xE2, 0xBB, 0xD9, 0x43, 0x73, 0x4F, 0x2E, 0x68, 0x8F, 0xC4, 0x55
    // };
    byte aad[16] = {
        0x02, 0x00,  // CA or (TCI, AN/SL)
        0x00, 0x01,  // PN = ...
        
        0xE8, 0xE2, 0xBB, 0xD9, 0x43, 0x73, 0x4F, 0x2E,
        0x68, 0x8F, 0xC4, 0x55
    };
    byte dst[6] = {0x00, 0x15, 0x5D, 0x21, 0xB2, 0x82};
    byte src[6] = {0x00, 0x15, 0x5d, 0x70, 0xab, 0xe5};

    std::string plaintext = "abcdefghijklmnop"; // 16 bytes
/*
reference: https://en.wikipedia.org/wiki/IEEE_802.1AE
MACsec frame format, which is similar to the Ethernet frame, but includes additional fields:
    - Security Tag, which is an extension of the EtherType
    - Message authentication code (Integrity Check Value, ICV)

The Security tag inside each frame in addition to EtherType includes:
    - A Connectivity Association (CA) number within the channel
    - A packet number (PN) to provide a unique initialization vector for encryption and authentication algorithms as well as protection against replay attacks
    - An optional LAN-wide Secure Channel Identifier (SCI), which is not required on point-to-point links.
*/    
    // Set IV from PN + SCI
    memcpy(iv, aad + 4, 12);
    std::string ciphertext = Encrypt(key, iv, plaintext, aad);
    // std::string ciphertext = plaintext;

    byte packet[1500] = {0};
    memcpy(packet, dst, 6);
    memcpy(packet + 6, src, 6);

    // EtherType
    packet[12] = (ETHER_TYPE_MACSEC >> 8) & 0xFF;
    packet[13] = ETHER_TYPE_MACSEC & 0xFF;

    // SecTAG (8 bytes) + SCI (8 bytes)
    memcpy(packet + 14, aad, 16);  // SecTAG + SCI
    
    memcpy(packet + 30, ciphertext.data(), ciphertext.size());

    // ICV (GCM tag is already appended in ciphertext)
    size_t total_len = 30 + ciphertext.size();
    StartClock();
    // for (int i = 0; i < 100; i++)
    // {
        if (pcap_sendpacket(handle, packet, total_len) != 0) {
            std::cerr << "pcap_sendpacket failed: " << pcap_geterr(handle) << std::endl;
            return 1;
        }
    // }
    EvaluateClock(true);
    std::cout << "MACsec frame with AES-GCM and ICV sent successfully.\n";
    pcap_close(handle);
    // frame structure:
    // 6 bytes - Destination MAC
    // 6 bytes - Source MAC
    // 2 bytes - EtherType (0x88E5)
    // 8 bytes - SecTAG (TCI, AN/SL)
    // 8 bytes - SCI (Source MAC + Port)
    // 16 bytes - Encrypted payload (ciphertext)
    // 16 bytes - ICV (GCM tag)
    std::cout << "Total packet length: " << total_len << " bytes.\n";
    return 0;
}
