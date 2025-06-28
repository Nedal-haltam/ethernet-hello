#include <iostream>

#include "ether.h"


int main(void)
{
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
    {
        SecByteBlock key(AES::DEFAULT_KEYLENGTH);
        byte iv[IV_LEN];
        std::string aad;
        ether::load(key, iv, aad, "key_iv_aad.bin");

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
}