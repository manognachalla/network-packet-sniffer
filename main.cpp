#include "main.hpp"
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0;
std::ofstream logfile("log.txt");

void logPacketInfo(std::ofstream &logfile, const struct iphdr* iph, int data_size) {
    if (logfile.is_open()) {
        logfile << "Packet received of size " << data_size << " bytes\n";
        logfile << "Source IP: " << inet_ntoa(*(struct in_addr*)&iph->saddr) << "\n";
        logfile << "Destination IP: " << inet_ntoa(*(struct in_addr*)&iph->daddr) << "\n";
        logfile << "Protocol: " << (unsigned int)iph->protocol << "\n";
    } 
    else {
        std::cerr << "Unable to open log.txt for writing." << std::endl;
    }
}

// Callback for processing captured packets
void ProcessPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int data_size = header->len; // Get the size of the packet

    // Print Ethernet header
    print_ethernet_header((unsigned char*)packet, data_size);

    // Get the IP header from the packet
    struct iphdr* iph = (struct iphdr*)(packet + sizeof(struct ethhdr)); // Assuming Ethernet header is first

    // Check if the IP header is valid
    if (data_size >= (sizeof(struct ethhdr) + sizeof(struct iphdr))) {
        // Check the protocol and print the corresponding packet details
        if (iph->protocol == IPPROTO_TCP) {
            print_tcp_packet((unsigned char*)packet, data_size); // Print TCP packet details
        } else if (iph->protocol == IPPROTO_UDP) {
            print_udp_packet((unsigned char*)packet, data_size); // Print UDP packet details
        } else if (iph->protocol == IPPROTO_ICMP) {
            print_icmp_packet((unsigned char*)packet, data_size); // Print ICMP packet details
        }

        // Log the packet information
        std::ofstream logfile("log.txt", std::ios::app); // Open in append mode
        logPacketInfo(logfile, iph, data_size);
        logfile.close();
    } else {
        std::cerr << "Received packet is too small to contain an IP header." << std::endl;
    }

    // Process the packet
    std::cout << "Packet received of size " << data_size << " bytes" << std::endl;
}

// Main function
int main() {
    std::ofstream logfile("log.txt");
    if (!logfile.is_open()) {
        std::cerr << "Unable to create log.txt file." << std::endl;
        return 1;
    }
    std::cout << "Starting..." << std::endl;

    // Set up pcap for packet capture
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("en0", BUFSIZ, 1, 10000, errbuf); // Replace "en0" with your network interface
    if (handle == nullptr) {
        std::cerr << "Could not open device for capturing: " << errbuf << std::endl;
        return 1;
    }

    // Start packet capture loop with callback to processPacket
    pcap_loop(handle, 0, ProcessPacket, nullptr);

    // Cleaning up
    pcap_close(handle);
    std::cout << "Finished" << std::endl;
    return 0;
}