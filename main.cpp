#include <iostream>
#include "ether.h"

#define USER_TYPE const char*

int main(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t * devs = EtherInitDevices();
    pcap_if_t *device = devs;
    std::cout << "Using device: " << device->name << std::endl;

    pcap_t *handle = EtherOpenDevice(devs, device, errbuf);

    // TODO: filter packets
    // struct bpf_program fp;
    // pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN);
    // pcap_setfilter(handle, &fp);

    const char *filename = "capture_output.pcap";
    pcap_dumper_t *dumper = pcap_dump_open(handle, filename);
    if (!dumper) {
        std::cerr << "Couldn't open dump file: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        pcap_freealldevs(devs);
        return 1;
    }

    auto PacketHandler_Writer = [](u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
        pcap_dump(user, h, bytes);
    };


    EtherCapturePackets(devs, handle, 10, PacketHandler_Writer, (u_char *)"User Info: Ethernet Hello");

    EtherClose(devs, handle);
    return 0;
}