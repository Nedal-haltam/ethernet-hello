#include <iostream>
#include "ether.h"

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t * devs = EtherInitDevices();
    pcap_if_t *device = devs;
    std::cout << "Using device: " << device->name << std::endl;

    pcap_t *handle = EtherOpenDevice(devs, device, errbuf);





    const char *filename = "capture_output.pcap";
    pcap_dumper_t *dumper = pcap_dump_open(handle, filename);
    if (!dumper) {
        std::cerr << "Couldn't open dump file: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        pcap_freealldevs(devs);
        return 1;
    }

    std::cout << "Capturing 10 packets and saving to " << filename << std::endl;

    // Callback that writes packets to the file
    auto write_packet = [](u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
        pcap_dump(user, h, bytes);
    };

    EtherCapturePackets(devs, handle, 10, write_packet, (u_char *)dumper);

    pcap_dump_close(dumper);
    EtherClose(devs, handle);
    return 0;
}
