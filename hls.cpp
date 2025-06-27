// sudo apt install libpcap-dev
// sudo apt install libcrypto++-dev
/*
Trying to compile Crypto++ with HLS is like trying to convert a novel into a circuit diagram — you're working at different abstraction levels.
*/
// TODO: 
//  - modify the code to make it compatible with intel HLS compiler
//      - remove dynamic memory interaction (e.g. memset, memcmp, memcpy, malloc, ...)
//      - make it simple c-code
//  - include "HLS/hls.h"
//  - include "HLS/stdio.h" instead of <stdio.h> to automatically omit `printf`s statements

#define GCM1_H

#ifdef GCM1_H
#include <stdio.h>
#include "gcm.h"

void PrintData(const uint8_t* data, const char* data_name, int data_len)
{
    printf("%s length: `%d`\n", data_name, data_len);
    printf("%s: ", data_name);
    for (int i = 0; i < data_len; i++)
        printf("%02X ", data[i]);
    printf("\n");
    printf("%s: `", data_name);
    for (int i = 0; i < data_len; i++)
        printf("%c", data[i]);
    printf("`\n");
}

#define PAYLOAD_LEN 10
#define KEY_LEN 16
#define IV_LEN 12
#define TAG_LEN 16
#define AUTH_DATA_LEN 18

int main(void) {

	/*parameter setting*/
    uint8_t key[KEY_LEN] = {
        0x8F, 0x7D, 0x5F, 0x7B, 0xB2, 0x86, 0xE7, 0x39, 0x73, 0x3A, 0x92, 0x0E, 0x7F, 0x91, 0xED, 0x95
    };

    uint8_t iv[IV_LEN] = {
        0xE8, 0xE2, 0xBB, 0xD9, 0x43, 0x73, 0x4F, 0x2E, 0x68, 0x8F, 0xC4, 0x55
    };

    PrintData(key, "key", KEY_LEN);
    PrintData(iv, "iv", IV_LEN);
    printf("---------------------------------------------------------\n");
	/*parameter setting*/
    AES_ctx ctx;
	AES_GCM_init(ctx, key, iv, IV_LEN);

    PrintData(ctx.H, "H", BL);
    PrintData(ctx.J0, "J0", BL);
    printf("---------------------------------------------------------\n");

    uint8_t input[PAYLOAD_LEN+1] = "abcdefghij";

	uint8_t A[AUTH_DATA_LEN+1] = "EthernetHeader_AAD";
	uint8_t T[TAG_LEN];

    PrintData(input, "Payload", PAYLOAD_LEN);
    printf("---------------------------------------------------------\n");
    AES_GCM_cipher(&ctx, input, PAYLOAD_LEN, A, AUTH_DATA_LEN, T, TAG_LEN);
    PrintData(input, "cipher", PAYLOAD_LEN);
    printf("---------------------------------------------------------\n");
    
    PrintData(T, "Tag", TAG_LEN);
    printf("---------------------------------------------------------\n");
    
	int ret = AES_GCM_Invcipher(&ctx, input, PAYLOAD_LEN, A, AUTH_DATA_LEN, T, TAG_LEN);
	if (ret) {
        PrintData(input, "Payload", PAYLOAD_LEN);
        printf("---------------------------------------------------------\n");
	}
	else {
        // TODO: raise a flag or do something in hardware
		return 1;
	}
    return 0;
}

#else

#include <stdio.h>
#include "gcm2.h"

int main(void)
{
    printf("hello, gcm 2\n");
    return 0;
}

#endif



