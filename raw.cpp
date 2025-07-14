#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>


#define INTERFACE_NAME "eth0"
int main() {
    int sockfd;
    char buffer[2048]; // buffer to store the frame

    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl failed");
        close(sockfd);
        return 1;
    }

    struct sockaddr_ll sa = {};
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_protocol = htons(ETH_P_ALL);

    if (bind(sockfd, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
        perror("bind failed");
        close(sockfd);
        return 1;
    }

    // Read packets
    while (true) {
        ssize_t num_bytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (num_bytes < 0) {
            perror("recvfrom failed");
            break;
        }

        struct ether_header *eth = (struct ether_header *)buffer;

        std::cout << "Ethernet Frame Received:" << std::endl;
        std::cout << "  Source MAC: " << ether_ntoa((struct ether_addr*)eth->ether_shost) << std::endl;
        std::cout << "  Destination MAC: " << ether_ntoa((struct ether_addr*)eth->ether_dhost) << std::endl;
        std::cout << "  EtherType: 0x" << std::hex << ntohs(eth->ether_type) << std::dec << std::endl;

        std::cout << "Payload Length: " << (num_bytes - sizeof(struct ether_header)) << " bytes\n" << std::endl;
    }

    close(sockfd);
    return 0;
}
