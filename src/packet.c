#include "../lib/packet.h"

#define PROTOCOL_NAME_LENGTH 200

void process_ipv4_packet(struct iphdr *ip_header){
    /* IP source address and IP destination address. */
    char packet_source[INET_ADDRSTRLEN];
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
    be layer 3 (for example, ICMP) 
    */
    int protocol_number = ip_header->protocol;

    switch(protocol_number){
        case IPPROTO_ICMP:
            /* ICMP (Internet Control Message Protocol) */
            strcpy(protocol_name, "ICMP"); // strcpy() adds '\0' character at the end, so this is correct.
            break;
        default:
            strcpy(protocol_name, "Unknown");
            break;
    }

    printf("Source: %s | ", packet_source);
    printf("Destination: %s | ", packet_destination);
    printf("Protocol: %s | ", protocol_name);
    printf("Length: %u bytes", ntohs(ip_header->tot_len)); // total length of the packet
}