#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>
#include "custom_algorithm.h"  // Include the custom algorithm header

FILE *data_file;  // File pointer for packet data file
FILE *data_csv_file;  // File pointer for packet data CSV file
pcap_dumper_t *dumper = NULL;  // Declare pcap dumper globally

#define MAX_CLASSIFICATION_SIZE 173000

volatile sig_atomic_t is_interrupted = 0;
int headings_printed = 0;  // Flag to check if CSV headings are printed
unsigned int sequence_counter = 0; // Sequence counter for UDP packets

void handle_interrupt(int signo) {
    is_interrupted = 1;
    // Close the pcap dump file on interruption
    if (dumper) {
        pcap_dump_close(dumper);
    }
    // Close the packet data file
    if (data_file) {
        fclose(data_file);
    }
    printf("Capture terminated.\n");
    exit(EXIT_SUCCESS);
}

void compute_udp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
    register unsigned long sum = 0;
    struct udphdr *udphdrp = (struct udphdr*)(ipPayload);
    unsigned short udpLen = htons(udphdrp->len);

    // Add the pseudo header
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += udphdrp->len;
    
    // Add the IP payload
    udphdrp->check = 0;
    while (udpLen > 1) {
        sum += *ipPayload++;
        udpLen -= 2;
    }

    // If any bytes left, pad the bytes and add
    if (udpLen > 0) {
        sum += ((*ipPayload)&htons(0xFF00));
    }

    // Fold sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    sum = ~sum;
    udphdrp->check = ((unsigned short)sum == 0x0000) ? 0xFFFF : (unsigned short)sum;
}

void packet_handler(const u_char *packet, size_t packet_len, struct pcap_pkthdr *pkthdr) {
    static unsigned int packet_number = 0; // Counter for packet number

    struct ethhdr *eth_header = (struct ethhdr *)packet;
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);
    uint8_t *udp_payload = (uint8_t *)(udp_header + 1);
    int udp_payload_size = ntohs(udp_header->len) - sizeof(struct udphdr);
printf("TTL: %u\n", ip_header->ttl);

    if (ip_header->protocol == IPPROTO_UDP) {
        packet_number++; // Increment packet number
        sequence_counter++; // Increment sequence counter
        printf("Sequence Number: %u\n", sequence_counter);


        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);

        char classification[MAX_CLASSIFICATION_SIZE];
        size_t classification_size = sizeof(classification);

        // Custom algorithm for UDP classification
        custom_algorithm(0, src_ip, ntohs(udp_header->source), dst_ip, ntohs(udp_header->dest), ip_header->protocol, pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1000000.0, packet_len, classification, classification_size);

        // Extract the UDP source checksum
        uint16_t src_checksum = ntohs(udp_header->check);
        printf("UDP Source Checksum: 0x%04x\n", src_checksum);

        // Calculate the UDP destination checksum
        compute_udp_checksum(ip_header, (unsigned short *)udp_header);
        uint16_t dest_checksum = ntohs(udp_header->check);
        printf("UDP Destination Checksum: 0x%04x\n", dest_checksum);
        if (src_checksum == dest_checksum) {
            printf("Packet Integrity retained\n");
        } else {
            printf("Alert! Packet Tampered with\n");
        }

        // Open packet data file for appending
        data_file = fopen("udp_packet_data.txt", "a");
        if (!data_file) {
            fprintf(stderr, "Error opening packet data file for writing\n");
            exit(EXIT_FAILURE);
        }

        // Write packet data to file
        fprintf(data_file, "Relative Time: %lf, Frame Length: %u, Packet Size: %zu bytes\n",
                pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 100000.0, (unsigned int)pkthdr->caplen, packet_len);
        fprintf(data_file, "Source IP: %s:%u, Destination IP: %s:%u, IP Protocol: %u\n",
                src_ip, ntohs(udp_header->source), dst_ip, ntohs(udp_header->dest), ip_header->protocol);

        // Close packet data file
        fclose(data_file);

        // Open CSV file for appending
        data_csv_file = fopen("packet_data.csv", "a");
        if (!data_csv_file) {
            fprintf(stderr, "Error opening packet data CSV file for writing\n");
            exit(EXIT_FAILURE);
        }

        // Write packet data to CSV file
        if (!headings_printed) { // Check if the headings have been printed
            fprintf(data_csv_file, "Packet Number,Timestamp,Relative Time,Source IP,Source Port,Destination IP,Destination Port,IP Protocol,Frame Length,Packet Size,Payload Size,Checksum,TTL,Sequence Number\n");
            headings_printed = 1; // Set flag to indicate headings have been printed
        }

        int ip_header_length = ip_header->ihl * 4;
        int udp_header_length = sizeof(struct udphdr);
        int payload_size = packet_len - (sizeof(struct ethhdr) + ip_header_length + udp_header_length);

        // Convert the timestamp to the desired format
        char timestamp[64];
        struct tm *tm_info = localtime(&pkthdr->ts.tv_sec);
        strftime(timestamp, sizeof(timestamp), "%b %d %Y %H:%M:%S", tm_info);

        // Add microseconds
        char timestamp_with_usec[80];
        snprintf(timestamp_with_usec, sizeof(timestamp_with_usec), "%s.%06ld IST", timestamp, pkthdr->ts.tv_usec);

      fprintf(data_csv_file, "%u,%s,%lf,%s,%u,%s,%u,%u,%u,%zu,%d,0x%04x,%u,%u\n",
        packet_number, // Packet number
        timestamp_with_usec, // Formatted timestamp
        pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1000000.0, // Relative time
        src_ip, // Source IP
        ntohs(udp_header->source), // Source port
        dst_ip, // Destination IP
        ntohs(udp_header->dest), // Destination port
        ip_header->protocol, // IP Protocol
        (unsigned int)pkthdr->caplen, // Frame length
        packet_len, // Packet size
        payload_size, // Payload size
        src_checksum, // Checksum
        ip_header->ttl, // TTL
        sequence_counter); // Sequence number


        // Close packet data CSV file
        fclose(data_csv_file);

        // Write the packet to the pcap dump file
        pcap_dump((u_char *)dumper, pkthdr, packet);
    }
}

int main() {
    int raw_socket;
    struct sockaddr_in saddr;
    socklen_t saddr_len = sizeof(saddr);
    uint8_t packet_buffer[65536];
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open a raw socket
    if ((raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
        perror("Error creating raw socket");
        exit(EXIT_FAILURE);
    }

    // Open a pcap dump file for writing
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65536);
    dumper = pcap_dump_open(handle, "socket_capture.pcap");
    if (!dumper) {
        fprintf(stderr, "Error opening pcap dump file for writing\n");
        exit(EXIT_FAILURE);
    }

    // Register the interrupt signal handler
    signal(SIGINT, handle_interrupt);

    // Print a message indicating the capture has started
    printf("Capture started. Press Ctrl+C to stop.\n");

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
        packet_handler(packet_buffer, packet_size, &pkthdr);
    }

    // Close the pcap dump file
    pcap_dump_close(dumper);

    // Close the raw socket
    close(raw_socket);

    printf("Capture terminated.\n");
    return 0;
}

