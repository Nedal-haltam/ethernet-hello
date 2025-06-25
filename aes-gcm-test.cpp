#include <iostream>

#include "ether.h"


int main(void)
{
    {
        SecByteBlock key1(AES::DEFAULT_KEYLENGTH);
        byte iv1[IV_LEN];
        std::string aad1 = "EthernetHeader_AAD";
        AutoSeededRandomPool prng;
        prng.GenerateBlock(key1, key1.size());
        prng.GenerateBlock(iv1, sizeof(iv1));
        
        save_and_print(key1, iv1, aad1);
        encrypt_decrypt_and_print(key1, iv1, aad1);
    }
    std::cout << "---------------------------------------------------------" << std::endl;
    {
        SecByteBlock key2(AES::DEFAULT_KEYLENGTH);
        byte iv2[IV_LEN];
        std::string aad2;
        load_and_print(key2, iv2, aad2);
        encrypt_decrypt_and_print(key2, iv2, aad2);
    }
}