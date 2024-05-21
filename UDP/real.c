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
#include "checksum.h"

FILE *data_file;  // File pointer for packet data file

#define MAX_CLASSIFICATION_SIZE 173000

volatile sig_atomic_t is_interrupted = 0;
pcap_dumper_t *dumper = NULL;  // Declare pcap dumper globally

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

#include "checksum.h"  // Include the UDP checksum validation header
void packet_handler(const u_char *packet, size_t packet_len, struct pcap_pkthdr *pkthdr);
void packet_handler(const u_char *packet, size_t packet_len, struct pcap_pkthdr *pkthdr) {
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);
    uint8_t *udp_payload = (uint8_t *)(udp_header + 1);
    int udp_payload_size = ntohs(udp_header->len) - sizeof(struct udphdr);

    if (ip_header->protocol == IPPROTO_UDP) {
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);

        char classification[MAX_CLASSIFICATION_SIZE];
        size_t classification_size = sizeof(classification);

        // Custom algorithm for UDP classification
        custom_algorithm(0, src_ip, ntohs(udp_header->source), dst_ip, ntohs(udp_header->dest),
                         ip_header->protocol, pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1000000.0, 
                         packet_len, classification, classification_size);

        // Check UDP checksum
        int is_checksum_valid = validate_udp_checksum(ip_header, udp_header, udp_payload, udp_payload_size);
        printf("UDP checksum is %s.\n", is_checksum_valid ? "valid" : "invalid");

        // Extracted UDP checksum
        uint16_t extracted_checksum = ntohs(udp_header->check);
        printf("Extracted UDP checksum: 0x%04x\n", extracted_checksum);

        // Manually calculate UDP checksum
        uint16_t calculated_checksum = calculate_checksum((uint16_t *)udp_header, sizeof(struct udphdr) / 2 + udp_payload_size / 2 + (udp_payload_size & 1));
        printf("Manually calculated UDP checksum: 0x%04x\n", calculated_checksum);

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
        fprintf(data_file, "Classification: %s\n", classification);
        fprintf(data_file, "Checksum Validation: %s\n", is_checksum_valid ? "Passed" : "Failed");
        fprintf(data_file, "Extracted UDP checksum: 0x%04x\n", extracted_checksum);
        fprintf(data_file, "Manually calculated UDP checksum: 0x%04x\n", calculated_checksum);

        // Close packet data file
        fclose(data_file);

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

