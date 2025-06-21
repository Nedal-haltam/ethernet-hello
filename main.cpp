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
    pcap_if_t * devs = EtherInitDevices();
    pcap_if_t *device = devs;
    std::cout << "Using device: " << device->name << std::endl;
    pcap_t *handle = EtherOpenDevice(devs, device, errbuf);

    // EtherPrintDevices(devs);
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
    pcap_dumper_t *user_info = EtherDumpOpen(devs, handle, filename);
#endif
    EtherCapturePackets(devs, handle, 50, PacketHandler, (u_char *)user_info);

    EtherClose(devs, handle);
    return 0;
}