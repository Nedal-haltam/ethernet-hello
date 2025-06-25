#include <iostream>
#include "ether.h"

void PacketHandlerWriter(u_char *user, const pcap_pkthdr *h, const u_char *bytes) {
    pcap_dump(user, h, bytes);
    auto user_info = "User Info: Ethernet Hello";
    ether::PacketHandler_Printer((u_char*)user_info, h, bytes);
}
const char* program_name;
void usage()
{
    std::cout << "Error: Device is not provided.\n\n";
    std::cout << "Usage: " << program_name << " -d <device> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -n <number>                 Number of packets to receive\n";
    exit(EXIT_FAILURE);
}

int main(int argc, char* argv[])
{
    int i = 0;
    program_name = argv[i];
    argc--; i++;
    const char* device = ether::InitDevices()->name;
    int NumberOfPackets = 20;
    while (argc > 0)
    {
        if (strcmp(argv[i], "-d") == 0)
        {
            argc--; i++;
            if (argc >= 1)
            {
                device = argv[i];
                argc--; i++;
            }
            else
            {
                usage();
            }
        }
        else if (strcmp(argv[i], "-n") == 0)
        {
            argc--; i++;
            if (argc >= 1)
            {
                NumberOfPackets = std::stoi(argv[i]);
                argc--; i++;
            }   
            else
            {
                usage();
            }
        }
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    std::cout << "Using device: " << device << std::endl;
    pcap_t *handle = ether::OpenDevice(NULL, device, errbuf, ether::PROMISC::RECEIVE);

    // ether::PrintDevices(ether::InitDevices());
    // return 0;
    // TODO: filter packets
    // bpf_program fp;
    // pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN);
    // pcap_setfilter(handle, &fp);

    CallBackType(PacketHandler) = PacketHandlerWriter;
    const char *filename = "capture_output.pcap";
    pcap_dumper_t *user_info = ether::DumpOpen(NULL, handle, filename);
    ether::CapturePackets(NULL, handle, NumberOfPackets, PacketHandler, (u_char *)user_info);

    ether::Close(NULL, handle);
    return 0;
}