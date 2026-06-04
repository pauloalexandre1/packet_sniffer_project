#ifndef PACKET_H
#define PACKET_H

#include <time.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <string.h>


/* Parse IPv4 datagram and print its contents. */
void process_ipv4_packet(struct iphdr *ip_header);

#endif