#include <iostream>
#include "ether.h"

void PacketHandlerWriter(u_char *user, const pcap_pkthdr *h, const u_char *bytes) {
    pcap_dump(user, h, bytes);
    auto user_info = "User Info: Ethernet Hello";
    PacketHandler_Printer((u_char*)user_info, h, bytes);
}

int main(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* device = "eth0";
    std::cout << "Using device: " << device << std::endl;
    pcap_t *handle = EtherOpenDevice(NULL, device, errbuf, PROMISC::SNIFF);

    // EtherPrintDevices(EtherInitDevices());
    // return 0;
    // TODO: filter packets
    // bpf_program fp;
    // pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN);
    // pcap_setfilter(handle, &fp);

    CallBackType(PacketHandler) = NULL;
#ifdef DEFAULT
    auto user_info = "User Info: Ethernet Hello";
#else
    PacketHandler = PacketHandlerWriter;
    const char *filename = "capture_output.pcap";
    pcap_dumper_t *user_info = EtherDumpOpen(NULL, handle, filename);
#endif
    EtherCapturePackets(NULL, handle, 20, PacketHandler, (u_char *)user_info);

    EtherClose(NULL, handle);
    return 0;
}