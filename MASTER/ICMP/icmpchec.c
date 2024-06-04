#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>

FILE *data_file; 

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
	
	if(ip_header->ip_p == IPPROTO_ICMP){
		struct icmp *icmp_header;
		char src_ip[INET_ADDRSTRLEN];
		char dst_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip_header->ip_src, src_ip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, INET_ADDRSTRLEN);	
		// Extracting checksum from the packet
		icmp_header = (struct icmp*)(packet+sizeof(struct ether_header) + ip_header->ip_hl*4);
		uint16_t stored_checksum = icmp_header->icmp_cksum;

		// Temporarily set checksum to 0 in the header
		icmp_header->icmp_cksum = 0;

		// Calculating the checksum
		uint16_t checksum = calculate_checksum((uint16_t*)icmp_header, ntohs(ip_header->ip_len) - ip_header->ip_hl * 4);

		// Restoring original checksum in the header
		icmp_header->icmp_cksum = stored_checksum;
		uint16_t checksum_host = ntohs(checksum);
		uint16_t stored_checksum_host = ntohs(stored_checksum);
		//printf("0x%X      0x%X\n", stored_checksum, checksum);
		//if(stored_checksum == checksum) printf("Yes checked!\n");
		//else printf("No not checked\n");
		//printf("Time to live is: %d\n", ip_header->ip_ttl);
		//data_file = fopen("udp_packet_data.txt", "a");
		//if (!data_file) {
        //    fprintf(stderr, "Error opening packet data file for writing\n");
        //    exit(EXIT_FAILURE);
        //}
        time_t x = pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 100000.0;
        struct tm * t;
  		t = localtime(&x);
  		char time[26];
  		strftime(time, sizeof(time), "%b %d %H:%M", t);
  		int total_len = ntohs(ip_header->ip_len);
  		int ip_header_length = ip_header->ip_hl*4;
  		int payload = total_len - ip_header_length - 8;
  		//printf("%s", time);
  		/*fprintf(data_file, "%s,%d,%s,-,%s,-,%d,%d,%d,%d,%d,0x%X\n", time, x, src_ip, dst_ip, IPPROTO_ICMP, (unsigned int)pkthdr->caplen, (unsigned int)pkthdr->caplen, payload, checksum);*/
  		//printf("%s,%d,%s,-,%s,-,%d,%d,%d,%d,%d,0x%X\n", time, x, src_ip, dst_ip, IPPROTO_ICMP, (unsigned int)pkthdr->caplen, //(unsigned int)pkthdr->caplen, payload, checksum);
  		//fprintf(data_file, "%d,", count);
  		fprintf(data_file, "%s,",time);
  		fprintf(data_file, "%d,",x);
  		fprintf(data_file, "%s,-,%s,-,",src_ip, dst_ip);
  		fprintf(data_file, "1,%d,%d,", (unsigned int)pkthdr->caplen,(unsigned int)pkthdr->caplen);
  		fprintf(data_file, "%d,", payload);
  		fprintf(data_file, "0x%X,", checksum);
  		fprintf(data_file, "0x%X,", stored_checksum);
  		fprintf(data_file, "Valid,%d\n",ip_header->ip_ttl);
  		fflush(data_file);
	}
}


int main() {
    pcap_t *handle;             // Session handle
    char *dev;                  // The device to sniff on
    char errbuf[PCAP_ERRBUF_SIZE];  // Error string
	data_file = fopen("icmp_packet_data.csv", "w");
	if (!data_file) {
            fprintf(stderr, "Error opening packet data file for writing\n");
            exit(EXIT_FAILURE);
        }
	//fprintf(data_file, "Timestamp,Relative Time,Source IP,Source Port,Destination IP,Destination Port,IP Protocol,Frame //Length,Packet Size,Payload Size,Checksum\n");
	fprintf(data_file, "Timestamp,Relative Time,Source IP,Source Port,Destination IP,Destination Port,IP Protocol,Frame Length,Packet Size,Payload Size,Src Checksum,Dest Checksum,Validity,TTL\n");
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
	fclose(data_file);
    return(0);
}
