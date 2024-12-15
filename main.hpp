#ifndef MAIN_HPP
#define MAIN_HPP
#include"queue.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <string>
#include <cstdio> //for perror
#include <cstdlib> //for exit//for rand()
#include <unistd.h> //for close
#include <climits>
#include <map>
#include <sys/socket.h>  // For socklen_t
#include <netinet/in.h> // For sockaddr_in
#include <arpa/inet.h>  // For inet_ntoa
#include <pcap.h>

extern int tcp, udp, icmp, others, igmp, total;
extern std::ofstream logfile;

//packet data structure
struct PacketData {
    const char* protocol;
    unsigned short sourcePort;
    unsigned short destPort;
    int size;
    const char* data;
};

extern std::ofstream logfile;

struct In_addr {
    unsigned long s_addr; //IP address in network byte order 
};

//ethernet header structure
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    unsigned short h_proto;
};

//IP header structure
struct iphdr {
    unsigned int ihl : 4;
    unsigned int version : 4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

//TCP header structure
struct tcphdr {
    unsigned short source;
    unsigned short dest;
    unsigned int seq;
    unsigned int ack_seq;
    unsigned short res1 : 4;
    unsigned short doff : 4;//dats offset
    unsigned short fin : 1;
    unsigned short syn : 1;
    unsigned short rst : 1;
    unsigned short psh : 1;
    unsigned short ack : 1;
    unsigned short urg : 1;
    unsigned short res2 : 2;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
};

//UDP header structure
struct udphdr {
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
};

//ICMP header structure
struct icmphdr {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short sequence;
};

//sockaddr_in structure
struct Sockaddr_in{
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned int sin_addr;
    char sin_zero[8];
};

//variables for packet statistics
struct Sockaddr{
    unsigned short sa_family; //address family
    char sa_data[14];   //protocol address
};

extern struct Sockaddr_in source;
extern struct Sockaddr_in dest;
extern int tcp, udp, icmp, others, igmp, total;

//buffer structure for routers
struct RouterBuffer{
    SimpleQueue<PacketData> buffer;  //buffer to hold packets
    int maxBufferSize;  //max buffer size

    RouterBuffer(int size);
};

//function declarations for packet processing
void ProcessPacket(unsigned char* buffer, int size);
void print_ethernet_header(unsigned char* buffer, int size);
void print_ip_header(unsigned char* buffer, int size);
extern void print_tcp_packet(unsigned char* buffer, int size);
void print_udp_packet(unsigned char* buffer, int size);
void print_icmp_packet(unsigned char* buffer, int size);
void PrintData(unsigned char* data, int size);

//socket function declarations
int create_socket(int domain, int type, int protocol);
int receive_from(int sockfd, void* buf, size_t len, int flags, struct Sockaddr* src_addr, socklen_t* addrlen);
int close_socket(int fd);
int socket(int domain, int type, int protocol) ;
int Recvfrom(int sockfd, void* buf, size_t len, int flags, struct Sockaddr* src_addr, socklen_t* addrlen);

#endif