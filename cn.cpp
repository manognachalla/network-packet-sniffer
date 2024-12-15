#include "main.hpp"

//socket functions
int socket(int domain, int type, int protocol) {
    int sock = ::socket(domain, type, protocol);
    if (sock < 0) {
        perror("Socket Error");
    }
    return sock;
}

int Recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen) {
    int bytes_received = ::recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    if (bytes_received < 0) {
        perror("Recvfrom Error");
    }
    return bytes_received;
}

int close(int fd) {
    int result = ::close(fd);
    if (result < 0) {
        perror("Close Error");
    }
    return result;
}


std::string intToIp(unsigned int ip) {
    return std::to_string((ip & 0xFF)) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 24) & 0xFF);
}

void ProcessPacket(unsigned char* buffer, int size){
    struct iphdr* iph= (struct iphdr*)(buffer+sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) {
        case 1:  //ICMP protocol
            ++icmp;
            print_icmp_packet(buffer, size);
            break;
        case 2:  
            ++igmp;//IGMP protocol
            break;
        case 6://tCP rotocol  
            ++tcp;
            print_tcp_packet(buffer, size);
            break;
        case 17: 
            ++udp;//UDP protocol
            print_udp_packet(buffer, size);
            break;
        default: 
            ++others;
            break;
    }
    logfile << "\nPacket Statistics:\n";
    logfile << "TCP : " << tcp << "   UDP : " << udp << "   ICMP : " << icmp 
            << "   IGMP : " << igmp << "   Others : " << others 
            << "   Total : " << total << "\n";
}

void print_ethernet_header(unsigned char* Buffer, int Size){
    struct ethhdr* eth= (struct ethhdr*)Buffer;
    logfile << "\nEthernet Header\n";
    logfile << "   |-Destination Address : " << std::hex//<< std::setw(2) << std::setfill('0')
            << static_cast<int>(eth->h_dest[0]) << "-"
            << static_cast<int>(eth->h_dest[1]) << "-"//
            << static_cast<int>(eth->h_dest[2]) << "-"
            << static_cast<int>(eth->h_dest[3]) << "-"
            << static_cast<int>(eth->h_dest[4]) << "-"
            << static_cast<int>(eth->h_dest[5]) << "\n";
    logfile << "   |-Source Address      : "
            << static_cast<int>(eth->h_source[0]) << "-"
            << static_cast<int>(eth->h_source[1]) << "-"
            << static_cast<int>(eth->h_source[2]) << "-"
            << static_cast<int>(eth->h_source[3]) << "-"
            << static_cast<int>(eth->h_source[4]) << "-"
            << static_cast<int>(eth->h_source[5]) << "\n";
    logfile << "   |-Protocol            : " << std::dec << (unsigned short)eth->h_proto << "\n";
}

void print_ip_header(unsigned char* Buffer, int Size) {
    print_ethernet_header(Buffer, Size);
    unsigned short iphdrlen;
    struct iphdr* iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    //define source and destination IP structures
    struct in_addr source, dest;
    source.s_addr = iph->saddr;
    dest.s_addr = iph->daddr;

    logfile << "\nIP Header\n";
    logfile << "   |-IP Version        : " << (unsigned int)iph->version << "\n";
    logfile << "   |-IP Header Length  : " << (unsigned int)iph->ihl << " DWORDS or " << (unsigned int)(iph->ihl) * 4 << " Bytes\n";
    logfile << "   |-Type Of Service   : " << (unsigned int)iph->tos << "\n";
    logfile << "   |-IP Total Length   : " << ntohs(iph->tot_len) << " Bytes(Size of Packet)\n";
    logfile << "   |-Identification    : " << ntohs(iph->id) << "\n";
    logfile << "   |-TTL               : " << (unsigned int)iph->ttl << "\n";
    logfile << "   |-Protocol          : " << (unsigned int)iph->protocol << "\n";
    logfile << "   |-Checksum          : " << ntohs(iph->check) << "\n";

    //use inet_ntoa to print source and destination IP addresses
    logfile << "   |-Source IP         : " << inet_ntoa(source) << "\n";
    logfile << "   |-Destination IP    : " << inet_ntoa(dest) << "\n";
}

void print_tcp_packet(unsigned char* Buffer, int Size){
    unsigned short iphdrlen;
    struct iphdr* iph=(struct iphdr*)(Buffer+sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct tcphdr* tcph=(struct tcphdr*)(Buffer+iphdrlen+sizeof(struct ethhdr));
    int header_size=sizeof(struct ethhdr)+iphdrlen+sizeof(tcph);

    logfile << "\n\n***********************TCP Packet*************************\n";
    print_ip_header(Buffer, Size);
    logfile << "\nTCP Header\n";
    logfile << "   |-Source Port      : " << ntohs(tcph->source) << "\n";
    logfile << "   |-Destination Port : " << ntohs(tcph->dest) << "\n";
    logfile << "   |-Sequence Number  : " << ntohl(tcph->seq) << "\n";
    logfile << "   |-Acknowledge Number : " << ntohl(tcph->ack_seq) << "\n";
    logfile << "   |-Header Length      : " << (unsigned int)tcph->doff << " DWORDS or " << (unsigned int)tcph->doff * 4 << " Bytes\n";
    logfile << "   |-FIN Flag         : " << (unsigned int)tcph->fin << "\n";
    logfile << "   |-RST Flag         : " << (unsigned int)tcph->rst << "\n";
    logfile << "   |-Synchronise Flag    : " << (unsigned int)tcph->syn << "\n";
    logfile << "   |-Finish Flag         : " << (unsigned int)tcph->fin << "\n";
    logfile << "   |-Window Size        : " << ntohs(tcph->window) << "\n";
    logfile << "   |-Checksum           : " << ntohs(tcph->check) << "\n";
    logfile << "   |-Urgent Pointer     : " << tcph->urg_ptr << "\n";
    logfile << "\nData Payload\n";
    PrintData(Buffer + header_size, Size - header_size);
}

void print_udp_packet(unsigned char* Buffer, int Size){
    unsigned short iphdrlen;
    struct iphdr* iph=(struct iphdr*)(Buffer + sizeof(struct ethhdr));
    iphdrlen=iph->ihl*4;

    struct udphdr* udph=(struct udphdr*)(Buffer+iphdrlen+sizeof(struct ethhdr));
    int header_size=sizeof(struct ethhdr)+iphdrlen+sizeof(udph);

    logfile << "\n\n***********************UDP Packet*************************\n";
    print_ip_header(Buffer, Size);
    logfile << "\nUDP Header\n";
    logfile << "   |-Source Port      : " << ntohs(udph->source) << "\n";
    logfile << "   |-Destination Port : " << ntohs(udph->dest) << "\n";
    logfile << "   |-UDP Length       : " << ntohs(udph->len) << "\n";
    logfile << "   |-Checksum         : " << ntohs(udph->check) << "\n";
    logfile << "\nData Payload\n";
    PrintData(Buffer + header_size, Size - header_size);
}

void print_icmp_packet(unsigned char* Buffer, int Size){
    unsigned short iphdrlen;
    struct iphdr* iph=(struct iphdr*)(Buffer+sizeof(struct ethhdr));
    iphdrlen=iph->ihl * 4;

    struct icmphdr* icmph=(struct icmphdr*)(Buffer+iphdrlen+sizeof(struct ethhdr));
    int header_size=sizeof(struct ethhdr)+iphdrlen+sizeof(icmph);

    logfile << "\n\n***********************ICMP Packet*************************\n";
    print_ip_header(Buffer, Size);
    logfile << "\nICMP Header\n";
    logfile << "   |-Type : " << (unsigned int)(icmph->type) << "\n";
    logfile << "   |-Code : " << (unsigned int)(icmph->code) << "\n";
    logfile << "   |-Checksum : " << ntohs(icmph->checksum) << "\n";
    logfile << "   |-ID : " << ntohs(icmph->id) << "\n";
    logfile << "   |-Sequence : " << ntohs(icmph->sequence) << "\n";
    logfile << "\nData Payload\n";
    PrintData(Buffer+header_size,Size-header_size);
}

void PrintData(unsigned char* data, int Size){
    int i, j;
    for(i=0; i<Size; i++){
        if(i!=0&&i%16==0){
            logfile<< "   ";
            for(j=i-16;j<i;j++){
                if(data[j]>=32&&data[j]<=128)
                    logfile<< (char)data[j];
                else
                    logfile<< ".";
            }
            logfile<< "\n";
        }
        if(i%16==0){
            logfile<< "   ";
        }
        logfile<< std::hex<< std::setw(2)<< (int)data[i]<< " ";
    }
    logfile<< "\n";
}

