#ifndef PACKET_H
#define PACKET_H

#include <time.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <string.h>
#include <linux/ipv6.h>

/* Parse IPv4 datagram and print its contents. */
void process_ipv4_packet(struct iphdr *ip_header);

/* Parse IPv6 datagram and print its contents. */
void process_ipv6_packet(struct ipv6hdr *ipv6_header);

#endif