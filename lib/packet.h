#ifndef PACKET_H
#define PACKET_H

#include <time.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <string.h>
#include <linux/ipv6.h>

/* Print common information about packet. */
void print_packet_information(char source_address[], char destination_address[], char protocol[], uint16_t total_length, char info[]);

/* Determine protocol's name based on protocol_number and store the result in buffer protocol_name */
void fill_out_protocol_name_buffer(int protocol_number, char* protocol_name);

/* Parse IPv4 datagram and print its contents. */
void process_ipv4_packet(struct iphdr *ip_header);

/* Parse IPv6 datagram and print its contents. */
void process_ipv6_packet(struct ipv6hdr *ipv6_header);

#endif