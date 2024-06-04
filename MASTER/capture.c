#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>/*
#include "custom_algorithm_tcp.h"
#include "custom_algorithm_udp.h"*/
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

int raw_socket;int upn=0,tpn=0;
struct sockaddr_in saddr;
socklen_t saddr_len = sizeof(saddr);
uint8_t packet_buffer[65536];
//pcap_dumper_t *dumper = NULL;
FILE *data_file;
FILE *packet_data_file;
FILE *ip_file;
FILE *tcp_data_txt_file;
FILE *tcp_data_csv_file;
FILE *udp_data_txt_file;
FILE *udp_data_csv_file;
FILE *packet_data_file;
pcap_dumper_t *dumper = NULL;
unsigned int pn = 0;
#define MAX_CLASSIFICATION_SIZE 173000
volatile sig_atomic_t is_interrupted = 0;
int tcp_headings_printed = 0;
int udp_headings_printed = 0;

void handle_interrupt(int signo) {

   is_interrupted = 1;
    if (dumper) pcap_dump_close(dumper);
    if (tcp_data_txt_file) fclose(tcp_data_txt_file);
    if (tcp_data_csv_file) fclose(tcp_data_csv_file);
    if (udp_data_txt_file) fclose(udp_data_txt_file);
    if (udp_data_csv_file) fclose(udp_data_csv_file);
    printf("Capture terminated.\n");
    exit(EXIT_SUCCESS);
}

void format_time(struct timeval ts, char *buffer, size_t buffer_size) {
    struct tm *tm_info = localtime(&ts.tv_sec);
    strftime(buffer, buffer_size, "%b %d %Y %H:%M:%S", tm_info);
    snprintf(buffer + strlen(buffer), buffer_size - strlen(buffer), ".%06ld IST", ts.tv_usec);
}
uint16_t calculate_tcp_checksum(struct iphdr *pIph, struct tcphdr *ipPayload) {
    unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl << 2);
    struct tcphdr *tcphdrp = ipPayload;

  sum += (pIph->saddr >> 16) & 0xFFFF;
    sum += (pIph->saddr) & 0xFFFF;
    sum += (pIph->daddr >> 16) & 0xFFFF;
    sum += (pIph->daddr) & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcpLen);
    tcphdrp->check = 0;
   unsigned short *ipPayload16 = (unsigned short *)ipPayload;
    while (tcpLen > 1) {
        sum += *ipPayload16++;
        tcpLen -= 2;
    }
 if (tcpLen > 0) {
     sum += ((*ipPayload16) & htons(0xFF00));
}

while (sum >> 16) {
     sum = (sum & 0xFFFF) + (sum >> 16);
}
sum = ~sum;
sum = htons((unsigned short)sum);
tcphdrp->check = (unsigned short)sum;
return (unsigned short)sum;
}
uint16_t compute_udp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
  register unsigned long sum = 0;
  struct udphdr *udphdrp = (struct udphdr *)(ipPayload);
  unsigned short udpLen = htons(udphdrp->len);
  sum += (pIph->saddr >> 16) & 0xFFFF;
  sum += (pIph->saddr) & 0xFFFF;
  sum += (pIph->daddr >> 16) & 0xFFFF;
  sum += (pIph->daddr) & 0xFFFF;
  sum += htons(IPPROTO_UDP);
  sum += udphdrp->len;
  udphdrp->check = 0;
 while (udpLen > 1) {
   sum += *ipPayload++;
   udpLen -= 2;
}
if (udpLen > 0) {
sum += ((*ipPayload) & htons(0xFF00));
}
while (sum >> 16) {
sum = (sum & 0xFFFF) + (sum >> 16);
}
 sum = ~sum;
 udphdrp->check = ((unsigned short)sum == 0x0000) ? 0xFFFF : (unsigned short)sum;
 return (unsigned short)sum;  // Return the checksum value
}
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

// Signal handler to handle interruption (Ctrl+C)
/*void handle_interrupt(int signo) {
 is_interrupted = 1;
// Close the pcap dump file on interruption
if (dumper) {
pcap_dump_close(dumper);
}
printf("Capture terminated.\n");
exit(EXIT_SUCCESS);
}*/
// Function to handle IP packets
void ip_handler(const u_char *packet, size_t packet_len, const struct pcap_pkthdr *pkthdr, FILE *output_file) {
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);
    ip_file = fopen("ip_data.csv", "a+");
    if(ip_file != NULL) {
        fseek(ip_file, 0, SEEK_END);
        int size = ftell(ip_file);

        if(size == 0) fprintf(ip_file, "Timestamp,Relative Time,Caplen,PacketLen,SrcIP,DestIP,Protocol,Version,IHL,TOS,TotalLen,ID,MoreFragments,FragmentOffset,Payload,Src Checksum,Dest Checksum,Validity,TTL\n");
                 
    }

    else{
        fprintf(stderr, "Error opening packet data file for writing\n");
        exit(EXIT_FAILURE);
    }
  
  int more_fragments = (ntohs(ip_header->frag_off) & IP_MF) != 0;

    // Write IP packet information to the output file

    time_t x = pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 100000.0;

    struct tm *t = localtime(&x);

    char time[26];

    strftime(time, sizeof(time), "%b %d %Y %H:%M:%S", t);

    uint16_t stored_checksum = ip_header->check;

    ip_header->check = 0;

    uint16_t checksum = calculate_checksum((uint16_t*)ip_header, ip_header->ihl * 4);

    ip_header->check = stored_checksum;

    char validity[100] = "";

    if(checksum == stored_checksum) strcpy(validity, "Valid");
        
    else strcpy(validity, "Invalid");

    int payload = ntohs(ip_header->tot_len) - ip_header->ihl * 4;
    
    fprintf(ip_file, "%s,%lf,%u,%zu,%s,%s,%u,%u,%u,%u,%u,%u,%d,%u,%d,0x%X,0x%X,%s,%d\n",

            time,
            
            pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1000000.0,

            (unsigned int)pkthdr->caplen,

            packet_len,

            src_ip,

            dst_ip,

            ip_header->protocol,

            (unsigned int)ip_header->version,

            (unsigned int)(ip_header->ihl * 4),

            (unsigned int)((ip_header->tos & 0xfc) >> 2),

            ntohs(ip_header->tot_len),

            ntohs(ip_header->id),

            more_fragments,

            (unsigned int)(ntohs(ip_header->frag_off) & 0x1fff),

            payload,

            stored_checksum,

            checksum, 
            
            validity, 

            (unsigned int)ip_header->ttl

    );
	
    fclose(ip_file);
}

// Function to handle ICMP packets

void icmp_handler(const u_char *packet, size_t packet_len, const struct pcap_pkthdr *pkthdr, FILE *data_file) {

    struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));

   // Check if the packet is an ICMP packet

    if (ip_header->ip_p == IPPROTO_ICMP) {

        struct icmp *icmp_header = (struct icmp*)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);

        char src_ip[INET_ADDRSTRLEN];

        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &ip_header->ip_src, src_ip, INET_ADDRSTRLEN);

        inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, INET_ADDRSTRLEN);

        // Calculate checksum for validation

       uint16_t stored_checksum = icmp_header->icmp_cksum;

        icmp_header->icmp_cksum = 0;

        uint16_t checksum = calculate_checksum((uint16_t*)icmp_header, ntohs(ip_header->ip_len) - ip_header->ip_hl * 4);

        icmp_header->icmp_cksum = stored_checksum;

        // Get timestamp for the packet

        time_t x = pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 100000.0;

        struct tm *t = localtime(&x);

        char time[26];

        strftime(time, sizeof(time), "%b %d %Y %H:%M:%S", t);

        int total_len = ntohs(ip_header->ip_hl);

        int ip_header_length = ip_header->ip_hl * 4;

        int payload = total_len - ip_header_length - 8;

        char validity[100] = "";

        if(checksum == stored_checksum) strcpy(validity, "Valid");
        
        else strcpy(validity, "Invalid");

        data_file = fopen("icmp_data.csv", "a+");

        if (!data_file) {

            fprintf(stderr, "Error opening packet data file for writing\n");

            exit(EXIT_FAILURE);

        }

        else{
            fseek(data_file, 0, SEEK_END);
            int size = ftell(data_file);

            if(size == 0) fprintf(data_file, "Timestamp,Relative Time,Source IP,Destination IP,IP Protocol,Frame Length,Packet Size,Payload Size,Src Checksum,Dest Checksum,Validity,TTL\n");
        }
       // Write ICMP packet information to the CSV file

        fprintf(data_file, "%s,%ld,%s,%s,1,%d,%d,%d,0x%X,0x%X,%s,%d\n",

                time, x, src_ip, dst_ip, (unsigned int)pkthdr->caplen, (unsigned int)pkthdr->caplen, payload, checksum, stored_checksum, validity, ip_header->ip_ttl);

        fflush(data_file);
	fclose(data_file);
    }

}

void handle_tcp_packet(const u_char *packet, size_t packet_len, const struct pcap_pkthdr *pkthdr) {

    struct ethhdr *eth_header = (struct ethhdr *)packet;

    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    size_t ip_header_length = ip_header->ihl * 4;
    
    int packet_number=0;

    if (ip_header->protocol == IPPROTO_TCP) {
        size_t tcp_header_length = tcp_header->doff * 4;

        size_t headers_length = ip_header_length + tcp_header_length;

        size_t payload_length = packet_len - headers_length;

       char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

       inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
       inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);

        uint16_t chs = ntohs(tcp_header->check);
	uint8_t ttl = ip_header->ttl;/*
        char classification[MAX_CLASSIFICATION_SIZE];

        size_t classification_size = sizeof(classification);*/

        printf("TCP packet captured\n");
/*

        custom_algorithm_tcp(tcp_header->th_flags, src_ip, ntohs(tcp_header->source), dst_ip, ntohs(tcp_header->dest), ip_header->protocol, ttl, pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1000000.0, packet_len, classification, classification_size);*/

        tcp_data_csv_file = fopen("tcp_packet_data.csv", "a");

        if (!tcp_data_csv_file) {

            fprintf(stderr, "Error opening TCP packet data CSV file for writing\n");

            exit(EXIT_FAILURE);

        }

        else{
            fseek(tcp_data_csv_file, 0, SEEK_END);
            int size = ftell(tcp_data_csv_file);

            if(size == 0)fprintf(tcp_data_csv_file, "Timestamp,Relative Time,Packet Size,Payload Length,Source IP,Source Port,Destination IP,Destination Port,IP Protocol,TCP Flags,TTL,Src Checksum,Dst Checksum,Validity\n");

        }

        char formatted_time[64];

        format_time(pkthdr->ts, formatted_time, sizeof(formatted_time));

        const char *validity = (chs == calculate_tcp_checksum(ip_header, tcp_header)) ? "Valid" : "Invalid";
        char flag_str[10];
        snprintf(flag_str, sizeof(flag_str), "0x%04X", ntohs(tcp_header->th_flags));

        fprintf(tcp_data_csv_file, "%s,%lf,%zu,%zu,%s,%u,%s,%u,%u,%s,%u,0x%04X,0x%04X,%s\n",

                formatted_time, pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1000000.0, packet_len,

                payload_length, src_ip, ntohs(tcp_header->source), dst_ip, ntohs(tcp_header->dest), ip_header->protocol,

                flag_str, ttl, chs, calculate_tcp_checksum(ip_header, tcp_header), validity);

        fclose(tcp_data_csv_file);

        pcap_dump((u_char *)dumper, pkthdr, packet);

    }

}

void handle_udp_packet(const u_char *packet, size_t packet_len, const struct pcap_pkthdr *pkthdr) {

    struct ethhdr *eth_header = (struct ethhdr *)packet;

    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);

    if (ip_header->protocol == IPPROTO_UDP) {

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);

        inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);
/*
        char classification[MAX_CLASSIFICATION_SIZE];
        size_t classification_size = sizeof(classification);

*/
        printf("UDP packet captured\n");
/*

        custom_algorithm_udp(ntohs(udp_header->source), ntohs(udp_header->dest), src_ip, dst_ip, packet_len, classification, classification_size);

*/

        udp_data_csv_file = fopen("udp_packet_data.csv", "a+");

        if (!udp_data_csv_file) {
            fprintf(stderr, "Error opening UDP packet data CSV file for writing\n");
            exit(EXIT_FAILURE);

        }
	else{
            fseek(udp_data_csv_file, 0, SEEK_END);
            int size = ftell(udp_data_csv_file);

            if(size == 0) fprintf(udp_data_csv_file, "Timestamp,Relative Time,Packet Size,Source IP,Source Port,Destination IP,Destination Port,IP Protocol,Src Checksum, Dst Checksum,Validity\n");

        }

        char formatted_time[64];

        format_time(pkthdr->ts, formatted_time, sizeof(formatted_time));

        uint16_t calculated_checksum = compute_udp_checksum(ip_header, (unsigned short*)udp_header);

        const char *validity = (udp_header->check == 0 || udp_header->check == calculated_checksum) ? "Valid" : "Invalid";

        fprintf(udp_data_csv_file, "%s,%lf,%zu,%s,%u,%s,%u,%u,0x%04X,0x%04X, %s\n",
                formatted_time, pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1000000.0, packet_len,
                src_ip, ntohs(udp_header->source), dst_ip, ntohs(udp_header->dest), ip_header->protocol,

                ntohs(udp_header->check), ntohs(calculated_checksum), validity);

        fclose(udp_data_csv_file);
        pcap_dump((u_char *)dumper, pkthdr, packet);
    }
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
//    static FILE *packet_data_file = NULL;
    static int packet_number = 0;
    char timestamp[64];
    time_t raw_time;
    struct tm *time_info;
    if (is_interrupted) {
        return;
    }
	   
		// Open the packet_data.csv file for writing (create it if it doesn't exist)
	packet_data_file = fopen("packet_data.csv", "a+");
	if (packet_data_file == NULL) {
	    printf("Error: Unable to create packet_data.csv\n");
	    return ;
	}
	// Write the header row if the file is empty
	fseek(packet_data_file, 0, SEEK_END);
	int size = ftell(packet_data_file);
	if (size == 0) {
	    fprintf(packet_data_file, "Timestamp,Relative_Time,Source IP,Source Port,Destination IP,Destination Port,Protocol,Packet Size,Payload Size\n");
	}
	// Close the file after finishing packet capture
	//fflush(packet_data_file);

	

	
   struct ethhdr *eth_header = (struct ethhdr *)packet;

    if (ntohs(eth_header->h_proto) == ETH_P_IP) {

        struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

        if (ip_header->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
            uint16_t src_port = ntohs(tcp_header->source);
            uint16_t dest_port = ntohs(tcp_header->dest);
            // Convert IP addresses to struct in_addr
           struct in_addr src_addr, dest_addr;
            src_addr.s_addr = ip_header->saddr;
            dest_addr.s_addr = ip_header->daddr;
            uint16_t payload_size = pkthdr->len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct tcphdr);
            // Format the timestamp
            raw_time = pkthdr->ts.tv_sec;
            time_info = localtime(&raw_time);
            strftime(timestamp, sizeof(timestamp), "%b %d %Y %H:%M:%S", time_info);
            snprintf(timestamp + strlen(timestamp), sizeof(timestamp) - strlen(timestamp), ".%06ld IST", pkthdr->ts.tv_usec);
            fprintf(packet_data_file, "%s,%ld.%06ld,%s,%u,%s,%u,TCP,%d,%u\n",timestamp, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec,
                    inet_ntoa(src_addr), src_port,
                    inet_ntoa(dest_addr), dest_port,
                    pkthdr->len, payload_size);
            handle_tcp_packet(packet, pkthdr->len, pkthdr);
        } 
        else if (ip_header->protocol == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
            uint16_t src_port = ntohs(udp_header->source);
            uint16_t dest_port = ntohs(udp_header->dest);
            // Convert IP addresses to struct in_addr
            struct in_addr src_addr, dest_addr;
            src_addr.s_addr = ip_header->saddr;
            dest_addr.s_addr = ip_header->daddr;
            uint16_t payload_size = pkthdr->len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr);
            // Format the timestamp
            raw_time = pkthdr->ts.tv_sec;
            time_info = localtime(&raw_time);
            strftime(timestamp, sizeof(timestamp), "%b %d %Y %H:%M:%S", time_info);
            snprintf(timestamp + strlen(timestamp), sizeof(timestamp) - strlen(timestamp), ".%06ld IST", pkthdr->ts.tv_usec);
            if ((src_port == 53) || (dest_port == 53))

                fprintf(packet_data_file, "%s,%ld.%06ld,%s,%u,%s,%u,DNS,%d,%u\n",timestamp, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec,

                        inet_ntoa(src_addr), src_port,
                        inet_ntoa(dest_addr), dest_port,
                        pkthdr->len, payload_size);
            else if ((src_port == 443) || (dest_port == 443))
                fprintf(packet_data_file, "%s,%ld.%06ld,%s,%u,%s,%u,QUIC,%d,%u\n",timestamp, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec,

                        inet_ntoa(src_addr), src_port,
                        inet_ntoa(dest_addr), dest_port,
                        pkthdr->len, payload_size);
            else
                fprintf(packet_data_file, "%s,%ld.%06ld,%s,%u,%s,%u,UDP,%d,%u\n",timestamp, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec,
                        inet_ntoa(src_addr), src_port,
                        inet_ntoa(dest_addr), dest_port,
                        pkthdr->len, payload_size);
            handle_udp_packet(packet, pkthdr->len, pkthdr);
        } 
        
        else {
            // Convert IP addresses to struct in_addr
            struct in_addr src_addr, dest_addr;
            src_addr.s_addr = ip_header->saddr;
            dest_addr.s_addr = ip_header->daddr;
             char *protocol_name = NULL;
            struct protoent *protocol_entry = getprotobynumber(ip_header->protocol);
            if (protocol_entry != NULL) {
                protocol_name = protocol_entry->p_name;
            } 
            
            else {
                protocol_name = "Unknown";
            }
	   int i;
	   for(i=0;i<strlen(protocol_name);i++) {
	   	protocol_name[i]-=32;
	   }
            // Format the timestamp
            raw_time = pkthdr->ts.tv_sec;
            time_info = localtime(&raw_time);
            strftime(timestamp, sizeof(timestamp), "%b %d %Y %H:%M:%S", time_info);
            snprintf(timestamp + strlen(timestamp), sizeof(timestamp) - strlen(timestamp), ".%06ld IST", pkthdr->ts.tv_usec);
            fprintf(packet_data_file, "%s,%ld.%06ld,%s,%u,%s,%u,%s,%d,%lu\n",timestamp, pkthdr->ts.tv_sec, pkthdr->ts.tv_usec,
            inet_ntoa(src_addr), 0,
                    inet_ntoa(dest_addr), 0,
                    protocol_name,
                    pkthdr->len, pkthdr->len - sizeof(struct ethhdr) - sizeof(struct iphdr));
 	}
        }
        
    ip_handler(packet, pkthdr->len, pkthdr, ip_file);
    icmp_handler(packet, pkthdr->len, pkthdr, data_file);
    packet_number++;
	fclose(packet_data_file);
}


int main() {
    char *pcap_file = "socket_capture.pcap";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65536);
    dumper = pcap_dump_open(handle, pcap_file);
    if (!dumper) {
        fprintf(stderr, "Error opening pcap dump file for writing\n");
        exit(EXIT_FAILURE);
    }
  
    // Open a raw socket
    if ((raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
        perror("Error creating raw socket");
        exit(EXIT_FAILURE);
    }
    signal(SIGINT, handle_interrupt);
    // Capture packets and handle them using packet_handler
    while (!is_interrupted) {
        ssize_t packet_size = recvfrom(raw_socket, packet_buffer, sizeof(packet_buffer), 0,
                                       (struct sockaddr *)&saddr, &saddr_len);
        if (packet_size == -1) {
            perror("Error receiving packet");
            continue; // Continue instead of exit to keep capturing
        }
        struct pcap_pkthdr pkthdr;
        pkthdr.ts.tv_sec = time(NULL);
        pkthdr.ts.tv_usec = 0;
        pkthdr.len = packet_size;
        pkthdr.caplen = packet_size;
        // Call packet_handler with the received packet
        packet_handler(packet_buffer, &pkthdr, packet_buffer);
    }
    // Close the pcap dump file
    pcap_dump_close(dumper);

    // Close the raw socket
    close(raw_socket);
    printf("Capture terminated.\n");
    return 0;
} 
