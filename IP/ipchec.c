#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>

// Function to calculate the checksum
uint16_t calculate_checksum(uint16_t *ptr, int nbytes) {
    uint32_t sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        sum += *((uint8_t*)ptr);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header;

    // Extracting IP header
    ip_header = (struct ip*)(packet + sizeof(struct ether_header));

    // Extracting checksum from the packet
    uint16_t stored_checksum = ip_header->ip_sum;

    // Temporarily set checksum to 0 in the header
    ip_header->ip_sum = 0;

    // Calculating the checksum
    uint16_t checksum = calculate_checksum((uint16_t*)ip_header, ip_header->ip_hl * 4);

    // Restoring original checksum in the header
    ip_header->ip_sum = stored_checksum;
	//uint16_t checksum_host = ntohs(checksum);
	//uint16_t stored_checksum_host = ntohs(stored_checksum);
	printf("0x%X      0x%X\n", stored_checksum, checksum);
	if(stored_checksum == checksum) printf("Yes checked!\n");
	else printf("No not checked\n");
}


int main() {
    pcap_t *handle;             // Session handle
    char *dev;                  // The device to sniff on
    char errbuf[PCAP_ERRBUF_SIZE];  // Error string

    // Define the device
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", dev);

    // Open the session in promiscuous mode
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the session
    pcap_close(handle);

    return(0);
}

