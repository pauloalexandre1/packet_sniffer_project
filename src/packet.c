#include "../lib/packet.h"

#define PROTOCOL_NAME_LENGTH 200
#define PACKET_INFO_LENGTH 400


void print_packet_information(char source_address[], char destination_address[], char protocol[], uint16_t total_length, char info[]){
    printf("Source: %s | ", source_address);
    printf("Destination: %s | ", destination_address);
    printf("Protocol: %s | ", protocol);
    printf("Length: %u bytes | ", total_length);
    printf("Info: %s", info);
}

void fill_out_protocol_name_buffer(int protocol_number, char* protocol_name){
    switch(protocol_number){
        case IPPROTO_ICMP:
            /* ICMP (Internet Control Message Protocol) */
            strcpy(protocol_name, "ICMP"); // strcpy() adds '\0' character at the end, so this is correct.
            break;
        case IPPROTO_TCP:
            /* TCP (Transmission Control Protocol) */
            strcpy(protocol_name, "TCP");
            break;
        case IPPROTO_UDP:
            /* UDP (User Datagram Protocol) */
            strcpy(protocol_name, "UDP");
            break;
        case IPPROTO_IPV6:
            /* 
            IPv6 datagrams may be encapsulated in IPv4 datagrams. 
            
            This happens when IPv6 datagrams pass through an IPv4 
            network.

            This process is called "tunneling".
            */
           strcpy(protocol_name, "IPv6");
           break;
        case IPPROTO_ICMPV6:
            /* ICMP for IPv6 */
            strcpy(protocol_name, "ICMP (v6)");
            break;
        default:
            strcpy(protocol_name, "Unknown");
            break;
    }
}

void process_ipv4_packet(struct iphdr *ip_header){
    /* Source IP address. */
    char packet_source[INET_ADDRSTRLEN];
    /* Destination IP address. */
    char packet_destination[INET_ADDRSTRLEN];

    struct in_addr source, dest;
    source.s_addr = ip_header->saddr;
    dest.s_addr = ip_header->daddr;

    /* Subsequent calls to inet_ntoa() will overwrite the same 
    buffer so copies to different buffers are carried out. */
    strcpy(packet_source, inet_ntoa(source));
    strcpy(packet_destination, inet_ntoa(dest));

    /* 
    'Time to live (TTL)' field in IPv4 datagram indicates the maximum 
    number of router hops the packet must go through. 
    
    This integer value is decremented by one unit with each hop until 
    it reaches 0.

    Useful for preventing endless circulation of a packet.
    */
    int time_to_live = ip_header->ttl;

    /* Upper-layer protocol name. */
    char protocol_name[PROTOCOL_NAME_LENGTH];

    /* 
    Number of protocol of data unit encapsulated in this 
    IPv4 datagram.
    
    Protocol in question could be upper-layer or could still 
    be layer 3 (for example, ICMP).
    */
    int protocol_number = ip_header->protocol;

    fill_out_protocol_name_buffer(protocol_number, protocol_name);

    print_packet_information(packet_source, packet_destination, protocol_name, ntohs(ip_header->tot_len), "N/A");
    
}

void process_ipv6_packet(struct ipv6hdr *ipv6_header){
    /* Source IP address. */
    char packet_source[INET6_ADDRSTRLEN];
    /* Destination IP address. */
    char packet_destination[INET6_ADDRSTRLEN];

    /* Place formatted IPv6 addresses in the respective buffers. */
    inet_ntop(AF_INET6, &(ipv6_header->saddr), packet_source, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6_header->daddr), packet_destination, INET6_ADDRSTRLEN);

    /* Upper-layer protocol name. */
    char protocol_name[PROTOCOL_NAME_LENGTH];

    /* 'Next header' field in IPv6 header determines next header (likely upper-layer protocol) */
    int protocol_number = (int) ipv6_header->nexthdr;

    fill_out_protocol_name_buffer(protocol_number, protocol_name);

    print_packet_information(packet_source, packet_destination, protocol_name, ntohs(ipv6_header->payload_len), "N/A");
}