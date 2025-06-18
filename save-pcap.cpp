#include <iostream>
#include <pcap.h>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs;

    // List devices
    if (pcap_findalldevs(&devs, errbuf) == -1 || devs == nullptr) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    pcap_if_t *device = devs;
    std::cout << "Using device: " << device->name << std::endl;

    // Open the device for capturing
    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Couldn't open device: " << errbuf << std::endl;
        pcap_freealldevs(devs);
        return 1;
    }

    // Open output file
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

    // Capture 10 packets
    pcap_loop(handle, 10, write_packet, (u_char *)dumper);

    // Clean up
    pcap_dump_close(dumper);
    pcap_close(handle);
    pcap_freealldevs(devs);

    std::cout << "Capture complete." << std::endl;
    return 0;
}
