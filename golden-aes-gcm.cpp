
#ifdef ECB
#include <iostream>
#include <iomanip>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>     // ECB_Mode
#include <cryptopp/filters.h>   // StringSource, StreamTransformationFilter
#define KEY_LEN 16
#define PAYLOAD_LEN 16
void ecb()
{    // Key and input data
    uint8_t key[KEY_LEN] = {
        0x8F, 0x7D, 0x5F, 0x7B, 0xB2, 0x86, 0xE7, 0x39,
        0x73, 0x3A, 0x92, 0x0E, 0x7F, 0x91, 0xED, 0x95
    };

    uint8_t input[PAYLOAD_LEN + 1] = {
        'a','b','c','d','e','f','g','h',
        'i','j','k','l','m','n','o','p','\0'
    };

    uint8_t output[PAYLOAD_LEN + 1] = {};
    uint8_t decrypted[PAYLOAD_LEN + 1] = {};

    // Encrypt
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption ecbEncrypt;
    ecbEncrypt.SetKey(key, KEY_LEN);

    CryptoPP::ArraySink cs(output, PAYLOAD_LEN);
    CryptoPP::ArraySource(input, PAYLOAD_LEN, true,
        new CryptoPP::StreamTransformationFilter(ecbEncrypt, new CryptoPP::Redirector(cs), CryptoPP::StreamTransformationFilter::NO_PADDING)
    );

    // Decrypt (to verify)
    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption ecbDecrypt;
    ecbDecrypt.SetKey(key, KEY_LEN);

    CryptoPP::ArraySink ds(decrypted, PAYLOAD_LEN);
    CryptoPP::ArraySource(output, PAYLOAD_LEN, true,
        new CryptoPP::StreamTransformationFilter(ecbDecrypt, new CryptoPP::Redirector(ds), CryptoPP::StreamTransformationFilter::NO_PADDING)
    );

    // Null-terminate
    output[PAYLOAD_LEN] = '\0';
    decrypted[PAYLOAD_LEN] = '\0';

    // Print
    std::cout << "Plaintext:  " << input << "\n";
    std::cout << "Encrypted:  ";
    for (int i = 0; i < PAYLOAD_LEN; ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)output[i] << " ";
    std::cout << "\n";

    std::cout << "Decrypted:  " << decrypted << "\n";
}
#else
#include <iostream>
#include "ether.h"
#endif


int main(void)
{
#ifdef ECB
    ecb();
    return 0;
#else
    {
        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        byte iv[IV_LEN];
        std::string aad1;
        ether::load(key, iv, aad1, "key_iv_aad.bin");
        byte aad[16] = {
            0x02, 0x00,  // CA or (TCI, AN/SL)
            0x00, 0x01,  // PN = ...
            
            0xE8, 0xE2, 0xBB, 0xD9, 0x43, 0x73, 0x4F, 0x2E,
            0x68, 0x8F, 0xC4, 0x55
        };

        std::cout << "key: ";
        for (int i = 0; i < AES::DEFAULT_KEYLENGTH; i++)
        {
            std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                    << (static_cast<unsigned int>(static_cast<unsigned char>(key.data()[i]))) << " ";
        }
        std::cout << std::endl;
        std::cout << "iv: ";
        for (int i = 0; i < IV_LEN; i++)
        {
            std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                    << (static_cast<unsigned int>(static_cast<unsigned char>(iv[i]))) << " ";
        }

        std::cout << std::dec << std::nouppercase << std::setfill(' ');
        std::cout << std::endl;
        ether::encrypt_decrypt_and_print(key, iv, aad);
    }
#endif
    // {
    //     SecByteBlock key1(AES::DEFAULT_KEYLENGTH);
    //     byte iv1[IV_LEN];
    //     std::string aad1 = "EthernetHeader_AAD";
    //     AutoSeededRandomPool prng;
    //     prng.GenerateBlock(key1, key1.size());
    //     prng.GenerateBlock(iv1, sizeof(iv1));
        
    //     ether::save_and_print(key1, iv1, aad1);
    //     ether::encrypt_decrypt_and_print(key1, iv1, aad1);
    // }
    // return 0;
    // std::cout << "---------------------------------------------------------" << std::endl;
}