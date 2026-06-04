#include "lib/packet.h"


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

    printf("\nSource: %s\n", packet_source);
    printf("\nDestination: %s\n", packet_destination);
}