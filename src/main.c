#include <stdio.h>
#include <stdlib.h>
#include "../lib/packet.h"
#include <sys/types.h>
#include <time.h>

/* 

Packet Sniffer written in C. 

*/

/* interface on which network-layer data unit (packet) will arrive. */
#define DEVICE_INTERFACE "wlp3s0"

/* amount of size of the packet to be captured (the number 65535 suggested in libcap man page). 
You can choose to read a selected range of bytes in the packet, hence the reason for this option. */
#define SNAPSHOT_LENGTH 65535

/* whether you want to capture traffic solely directed to the abovementioned interface or other 
traffic present included (0 - the former; 1 - the latter). */
#define PROMISCUOUS_MODE 0 

/* Time (in milliseconds) taken for arriving packets to be buffered before being delivered to 
the application (important for efficiency). */
#define PACKET_BUFFER_TIMEOUT 100

/* Maximum number of packets to be read during sniffing */
#define NR_PACKETS_TO_BE_READ 500

int datalink_header_length = 0;

/* Print timestamp. */
void print_timestamp(struct tm *nowtm){
    printf("\n %d:%d | ", nowtm->tm_hour, nowtm->tm_min);
}

/* Parse data-link frame header to get actual packet. */
void process_packet(__u_char* user_arg, const struct pcap_pkthdr* pkthdr, const __u_char* packet_ptr){
    time_t nowtime = pkthdr->ts.tv_sec;
    struct tm *nowtm = localtime(&nowtime);

    const struct ethhdr *frame = (const struct ethhdr*) packet_ptr;

    /* Skip the data-link header and start at the payload (usually IP) */
    packet_ptr = packet_ptr + datalink_header_length;

    /* 
    Network-layer datagram type ID (or any numerical value 
    being transmitted on a network) might arrive in a different 
    byte order (it arrives in "network byte order", ie. big endian). 
    
    For example, if the packet ID is 0x0800 (IPv4), then, in a 
    little-endian machine, this value will be interpreted as 
    0x0008 (not IPv4).

    The ntohs() call ensures that the value is read correctly. 
    From the example above: if the machine this program runs on 
    is little-endian, then bytes 08 and 80 will be swapped. 
    Otherwise, the order remains the same, as the machine is 
    already in the same byte order as the network.
    */
    uint16_t packet_type = ntohs(frame->h_proto);

    switch(packet_type){
        /* IPv4 */
        case ETH_P_IP:
            struct iphdr *ip_header = (struct iphdr*) packet_ptr;
            print_timestamp(nowtm);
            process_ipv4_packet(ip_header);
            break;
        /* IPv6 */
        case ETH_P_IPV6:
            printf("\nThis is an IPv6 packet!\n");
            break;
        /* ARP (Address Resolution Protocol) */
        case ETH_P_ARP:
            printf("\nThis is an ARP packet!\n");
            break;
        default:
            printf("\nCan't work with this packet type! Packet type: 0x%04X\n", packet_type);
            break;
    }

    
}

int main(int argc, const char* argv[]){

    /* Buffer to store errors. */
    char error_buffer[PCAP_ERRBUF_SIZE];

    /* Man page for pcap_open_live() function recommends error_buffer to be initially set 
    to 'zero-length string' in order to detect a warning (not error) caused by calling 
    pcap_open_live(). */
    error_buffer[0] = '\0';

    /* Open device DEVICE_INTERFACE for reading packets */
    pcap_t* handle = pcap_open_live(DEVICE_INTERFACE, SNAPSHOT_LENGTH, PROMISCUOUS_MODE, PACKET_BUFFER_TIMEOUT, error_buffer);

    if (handle == NULL){
        printf("ERROR: An error ocurred while calling pcap_open_live()! Error message: \"%s\".\n", error_buffer);
        return -1;
    }

    /* If pcap_open_live() call succeeded and the error buffer is not empty, then a warning 
    was written to the buffer instead and needs to be displayed. */

    else if (error_buffer[0] != '\0'){
        printf("\nWARNING: A warning was generated after calling pcap_open_live(). Warning message: \"%s\".\n", error_buffer);
    }

    /* Determine the type of the frame header received. */
    int datalink_header_type = pcap_datalink(handle);

    /* 
    You can add more options depending on the data-link header type 
    of the frame you receive on interface DEVICE_INTERFACE.
    */

    switch(datalink_header_type){
        case DLT_NULL:
            datalink_header_length = 4; // 4 bytes for loopback header
            break;
        case DLT_EN10MB:
            /* IEEE 802.3 Ethernet (10 Mb) */
            datalink_header_length = 14; // 14 bytes (fixed length)
            break;
        default:
            datalink_header_length = 0;
            break;
    }

    /* Process NR_PACKETS_TO_BE_READ packets arriving on handle device. */
    /* pcap_loop() returns 0 on success. */

    if ((pcap_loop(handle, NR_PACKETS_TO_BE_READ, process_packet, (__u_char*) NULL))){
        printf("\nERROR: pcap_loop() failed!\n");
        return -1;
    }

    return 0;
}