#include <iostream>
#include <string>
#include <crypto++/aes.h>
#include <crypto++/gcm.h>
#include <crypto++/osrng.h>
#include <crypto++/hex.h>

int main() {
    using namespace CryptoPP;

    // Sample key and IV (usually from secure key exchange)
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, key.size());

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    std::string plain = "This is the Ethernet payload";
    std::string cipher, encoded, recovered;

    // Encrypt and authenticate
    try {
        GCM<AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

        AuthenticatedEncryptionFilter ef(enc,
            new StringSink(cipher), false, 16 // 128-bit tag
        );

        // Optional associated data (AAD), such as the Ethernet header
        std::string aad = "EthernetHeader";
        ef.ChannelPut("AAD", (const byte*)aad.data(), aad.size());
        ef.ChannelMessageEnd("AAD");

        ef.ChannelPut("", (const byte*)plain.data(), plain.size());
        ef.ChannelMessageEnd("");
    } catch (const Exception& e) {
        std::cerr << "Encryption error: " << e.what() << std::endl;
        return 1;
    }

    // Decrypt and verify
    try {
        GCM<AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

        AuthenticatedDecryptionFilter df(dec,
            new StringSink(recovered),
            AuthenticatedDecryptionFilter::THROW_EXCEPTION, 16
        );

        std::string aad = "EthernetHeader"; // Must be same as above
        df.ChannelPut("AAD", (const byte*)aad.data(), aad.size());
        df.ChannelMessageEnd("AAD");

        df.ChannelPut("", (const byte*)cipher.data(), cipher.size());
        df.ChannelMessageEnd("");

        std::cout << "Recovered: " << recovered << std::endl;
    } catch (const Exception& e) {
        std::cerr << "Decryption failed: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
