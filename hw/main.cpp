#include <HLS/hls.h>
#include <HLS/hls_avalon.h>
#include <stdint.h>

typedef struct {
    uint64_t data;
    bool     last;
} ethernet_word;

hls_avalon_stream<ethernet_word> & __restrict input,
hls_avalon_stream<ethernet_word> & __restrict output

void ethernet_parser(
    hls_avalon_stream<ethernet_word> &input,
    hls_avalon_stream<ethernet_word> &output,
    uint64_t *dst_mac,
    uint64_t *src_mac,
    uint16_t *eth_type)
{
#pragma HLS INTERFACE hls_avalon_stream port=input
#pragma HLS INTERFACE hls_avalon_stream port=output
#pragma HLS INTERFACE m10k port=dst_mac
#pragma HLS INTERFACE m10k port=src_mac
#pragma HLS INTERFACE m10k port=eth_type
#pragma HLS COMPONENT

    bool header_done = false;
    ethernet_word word;

    // Read until end of packet
    while (!header_done || !input.empty()) {
        word = input.read();

        if (!header_done) {
            // First word contains dst_mac[47:0] and src_mac[15:0]
            *dst_mac = (word.data >> 16) & 0xFFFFFFFFFFFFULL;
            *src_mac = ((word.data & 0xFFFFULL) << 32);
            header_done = true;
        } else {
            // Second word: src_mac[31:0] and EtherType[15:0]
            *src_mac |= (word.data >> 32) & 0xFFFFFFFFULL;
            *eth_type = (word.data >> 16) & 0xFFFF;

            // Optionally forward the data
            output.write(word);
        }

        if (word.last) break;
    }
}

int main() {
    hls_avalon_stream<ethernet_word> input, output;
    uint64_t dst_mac = 0;
    uint64_t src_mac = 0;
    uint16_t eth_type = 0;

    // Simulated input
    ethernet_word w0 = { .data = 0x1122334455667788ULL, .last = false };
    ethernet_word w1 = { .data = 0x99AABBCCDD008000ULL, .last = true };

    input.write(w0);
    input.write(w1);

    ethernet_parser(input, output, &dst_mac, &src_mac, &eth_type);

    printf("Dst MAC: %012llx\n", dst_mac);
    printf("Src MAC: %012llx\n", src_mac);
    printf("EthType: %04x\n", eth_type);

    return 0;
}
