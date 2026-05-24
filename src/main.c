#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
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
#define NR_PACKETS_TO_BE_READ 10


void process_packet(__u_char* user_arg, const struct pcap_pkthdr* pkthdr, const __u_char* packet_ptr){
    time_t nowtime = pkthdr->ts.tv_sec;
    struct tm *nowtm = localtime(&nowtime);

    printf("\n %d/%d | %d:%d - A packet has arrived (size: %u bytes)!\n", nowtm->tm_mday, nowtm->tm_mon+1, nowtm->tm_hour, nowtm->tm_min, pkthdr->len);
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

    /* Process NR_PACKETS_TO_BE_READ packets arriving on handle device. */
    /* pcap_loop() returns 0 on success. */

    if ((pcap_loop(handle, NR_PACKETS_TO_BE_READ, process_packet, (__u_char*) NULL))){
        printf("\nERROR: pcap_loop() failed!\n");
        return -1;
    }

    return 0;
}