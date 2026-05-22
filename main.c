#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

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



int main(int argc, const char* argv[]){

    /* Buffer to store errors. */
    char* error_buffer[PCAP_ERRBUF_SIZE];

    /* Open device DEVICE_INTERFACE for reading packets */
    pcap_t* handle = pcap_open_live(DEVICE_INTERFACE, SNAPSHOT_LENGTH, PROMISCUOUS_MODE, PACKET_BUFFER_TIMEOUT, error_buffer);

    return 0;
}