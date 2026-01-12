
#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Function to process each captured packet
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Skip Ethernet header (14 bytes) to get to the IP header
    struct ip *ip_header = (struct ip *)(packet + 14);

    std::cout << "--- New Packet Captured ---" << std::endl;
    std::cout << "Length: " << header->len << " bytes" << std::endl;
    // Convert network byte order IP addresses to human-readable strings
    std::cout << "Source IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
    std::cout << "Dest IP:   " << inet_ntoa(ip_header->ip_dst) << std::endl;
    std::cout << "---------------------------" << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer for error messages
    pcap_if_t *interfaces, *temp;  // Linked list for network interfaces

    // Find all available network devices (interfaces)
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "🛡️ C++ Network Security Tool Active" << std::endl;
    // Use the first found interface for sniffing
    std::cout << "Monitoring Interface: " << interfaces->name << std::endl;

    // Open the first device for sniffing
    // parameters: interface name, snaplen, promiscuous mode, timeout, error buffer
    pcap_t *descr = pcap_open_live(interfaces->name, BUFSIZ, 1, 1000, errbuf);
    if (descr == NULL) {
        std::cerr << "pcap_open_live() failed: " << errbuf << std::endl;
        return 1;
    }

    // Start capturing packets
    // parameters: descriptor, number of packets to capture, packet handler function, arguments to handler
    pcap_loop(descr, 10, packet_handler, NULL); // Capture 10 packets

    std::cout << "✅ Capture Complete." << std::endl;

    // Free the device list
    pcap_freealldevs(interfaces);
    pcap_close(descr);

    return 0;
}
