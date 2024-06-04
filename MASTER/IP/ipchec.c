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

    // Extracting checksum from the packet
    uint16_t stored_checksum = ip_header->ip_sum;

    // Temporarily set checksum to 0 in the header
    ip_header->ip_sum = 0;

    // Calculating the checksum
    uint16_t checksum = calculate_checksum((uint16_t*)ip_header, ip_header->ip_hl * 4);

    // Restoring original checksum in the header
    ip_header->ip_sum = stored_checksum;
    char src_ip[INET_ADDRSTRLEN];
		char dst_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &ip_header->ip_src, src_ip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, INET_ADDRSTRLEN);
		time_t x = pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 100000.0;
        struct tm * t;
  		t = localtime(&x);
  		char time[26];
  		strftime(time, sizeof(time), "%b %d %H:%M", t);
  		int total_len = ntohs(ip_header->ip_len);
  		int ip_header_length = ip_header->ip_hl*4;
  		int payload = total_len - ip_header_length;
	//uint16_t checksum_host = ntohs(checksum);
	//uint16_t stored_checksum_host = ntohs(stored_checksum);
	//printf("0x%X      0x%X\n", stored_checksum, checksum);
	//if(stored_checksum == checksum) printf("Yes checked!\n");
	//else printf("No not checked\n");
    //printf("Time to live is: %d\n", ip_header->ip_ttl);
	int src_port = 0, dest_port = 0;
    if(ip_header->ip_p == IPPROTO_TCP){
    	struct tcphdr *tcp_header = (struct tcphdr *)(packet + ip_header_length);
    	src_port = ntohs(tcp_header->source);
    	dest_port = ntohs(tcp_header->dest);
    	fprintf(data_file, "%s,",time);
  		fprintf(data_file, "%d,",x);
  		fprintf(data_file, "%s,%d,%s,%d,",src_ip, src_port, dst_ip, dest_port);
  		fprintf(data_file, "0,%d,%d,", (unsigned int)pkthdr->caplen,(unsigned int)pkthdr->caplen);
  		fprintf(data_file, "%d,", payload);
  		fprintf(data_file, "0x%X,", checksum);
  		fprintf(data_file, "0x%X,", stored_checksum);
  		fprintf(data_file, "Valid,%d\n",ip_header->ip_ttl);
  		fflush(data_file);
    }
    
    if(ip_header->ip_p == IPPROTO_UDP){
    	struct udphdr *tcp_header = (struct udphdr *)(packet + ip_header_length);
    	src_port = ntohs(tcp_header->source);
    	dest_port = ntohs(tcp_header->dest);
    	fprintf(data_file, "%s,",time);
  		fprintf(data_file, "%d,",x);
  		fprintf(data_file, "%s,%d,%s,%d,",src_ip, src_port, dst_ip, dest_port);
  		fprintf(data_file, "0,%d,%d,", (unsigned int)pkthdr->caplen,(unsigned int)pkthdr->caplen);
  		fprintf(data_file, "%d,", payload);
  		fprintf(data_file, "0x%X,", checksum);
  		fprintf(data_file, "0x%X,", stored_checksum);
  		fprintf(data_file, "Valid,%d\n",ip_header->ip_ttl);
  		fflush(data_file);
    }
    
    if(ip_header->ip_p == IPPROTO_ICMP){
    	fprintf(data_file, "%s,",time);
  		fprintf(data_file, "%d,",x);
  		fprintf(data_file, "%s,-,%s,-,",src_ip, dst_ip);
  		fprintf(data_file, "0,%d,%d,", (unsigned int)pkthdr->caplen,(unsigned int)pkthdr->caplen);
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
	data_file = fopen("ip_packet_data.csv", "w");
    // Define the device
    fprintf(data_file, "Timestamp,Relative Time,Source IP,Source Port,Destination IP,Destination Port,IP Protocol,Frame Length,Packet Size,Payload Size,Src Checksum,Dest Checksum,Validity,TTL\n");
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
