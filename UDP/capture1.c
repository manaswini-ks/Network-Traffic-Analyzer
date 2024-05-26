#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include "custom_algorithm.h"

FILE *data_txt_file;  // File pointer for packet data text file
FILE *data_csv_file;  // File pointer for packet data CSV file
pcap_dumper_t *dumper = NULL;  // Declare pcap dumper globally

#define MAX_CLASSIFICATION_SIZE 173000

volatile sig_atomic_t is_interrupted = 0;
int headings_printed = 0; // Flag to track if headings have been printed in CSV file

void handle_interrupt(int signo) {
    is_interrupted = 1;

    // Close the pcap dump file on interruption
    if (dumper) {
        pcap_dump_close(dumper);
    }

    // Close the packet data text file
    if (data_txt_file) {
        fclose(data_txt_file);
    }

    // Close the packet data CSV file
    if (data_csv_file) {
        fclose(data_csv_file);
    }

    printf("Capture terminated.\n");
    exit(EXIT_SUCCESS);
}

void packet_handler(const u_char *packet, size_t packet_len, struct pcap_pkthdr *pkthdr) {
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    if (ip_header->protocol == IPPROTO_TCP) {
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);

        char classification[MAX_CLASSIFICATION_SIZE];
        size_t classification_size = sizeof(classification);

        // Pass the TTL to custom_algorithm
        custom_algorithm(tcp_header->th_flags, src_ip, ntohs(tcp_header->source), dst_ip, ntohs(tcp_header->dest),
                         ip_header->protocol,  packet_len,
                         classification, classification_size);

        // Open packet data text file for appending
        data_txt_file = fopen("packet_data.txt", "a");
        if (!data_txt_file) {
            fprintf(stderr, "Error opening packet data text file for writing\n");
            exit(EXIT_FAILURE);
        }

        // Write packet data to text file
        fprintf(data_txt_file, "Relative Time: %lf, Frame Length: %u, Packet Size: %zu bytes\n",
                pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1000000.0, (unsigned int)pkthdr->caplen, packet_len);
        fprintf(data_txt_file, "Source IP: %s:%u, Destination IP: %s:%u, IP Protocol: %u\n", src_ip,
                ntohs(tcp_header->source), dst_ip, ntohs(tcp_header->dest), ip_header->protocol);
        fprintf(data_txt_file, "Classification: %s\n", classification); // Append classification

        // Close packet data text file
        fclose(data_txt_file);

        // Open packet data 
        
         //file for appending
        data_csv_file = fopen("packet_data.csv", "a");
        if (!data_csv_file) {
            fprintf(stderr, "Error opening packet data CSV file for writing\n");
            exit(EXIT_FAILURE);
        }
// Write packet data to CSV file
if (!headings_printed) { // Check if the headings have been printed
    fprintf(data_csv_file, "Relative Time,Frame Length,Packet Size,Source IP,Source Port,Destination IP,Destination Port,IP Protocol,TTL,TCP Flags,Classification\n");
    headings_printed = 1; // Set flag to indicate headings have been printed
}
// Convert TCP flags to hexadecimal representation
char flag_str[10];
snprintf(flag_str, sizeof(flag_str), "0x%04X", ntohs(tcp_header->th_flags));

// Print individual TCP flags and TTL in the "TCP Flags" and "TTL" columns
fprintf(data_csv_file, "%lf,%u,%zu,%s,%u,%s,%u,%u,%u,%s,%s\n",
        pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1000000.0, // Relative time
        (unsigned int)pkthdr->caplen, // Frame length
        packet_len, // Packet size
        src_ip, // Source IP
        ntohs(tcp_header->source), // Source port
        dst_ip, // Destination IP
        ntohs(tcp_header->dest), // Destination port
        ip_header->protocol, // IP Protocol
        ip_header->ttl, // TTL
        flag_str, // TCP flags
        classification); // Classification

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
    uint8_t packet_buffer[65536];  // Adjust this size based on your needs
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
            close(raw_socket);
            exit(EXIT_FAILURE);
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

