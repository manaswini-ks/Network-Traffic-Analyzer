#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h> // Include for timestamp
#include "icmpattack.h"

void packet_handler(const u_char *packet, size_t packet_len, size_t ip_len);

int main() {
    int raw_socket;
    struct sockaddr_in saddr;
    socklen_t saddr_len = sizeof(saddr);
    uint8_t packet_buffer[65536];  // Adjust this size based on your needs

    // Open a raw socket to capture ICMP traffic
    if ((raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("Error creating raw socket");
        exit(EXIT_FAILURE);
    }

    // Capture ICMP packets
    while (1) {
        ssize_t packet_size = recvfrom(raw_socket, packet_buffer, sizeof(packet_buffer), 0,
                                       (struct sockaddr *)&saddr, &saddr_len);
        if (packet_size == -1) {
            perror("Error receiving packet");
            close(raw_socket);
            exit(EXIT_FAILURE);
        }

        // Call packet_handler with the received packet
        packet_handler(packet_buffer, packet_size, sizeof(struct iphdr));
    }

    // Close the raw socket
    close(raw_socket);

    // Now, call the detect_dos_attack function
    detect_dos_attack("packet_info.csv", 100);

    return 0;
}

void packet_handler(const u_char *packet, size_t packet_len, size_t ip_len) {
    // Assuming IP header + ICMP header structure
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + ip_len);

    // Extract IP header fields
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
    
    // Extract ICMP header fields
    uint16_t checksum = ntohs(icmp_header->checksum);
    uint16_t id = ntohs(icmp_header->un.echo.id);
    uint16_t sequence = ntohs(icmp_header->un.echo.sequence);

    // Open CSV file for appending if it's not the first packet, otherwise open it for writing
    FILE *csv_file = fopen("packet_info.csv", (packet_len > 0) ? "a" : "w");
    if (csv_file == NULL) {
        perror("Error opening CSV file");
        return;
    }

    // Open text file for appending if it's not the first packet, otherwise open it for writing
    FILE *txt_file = fopen("packet_info.txt", "a");
    if (txt_file == NULL) {
        perror("Error opening text file");
        fclose(csv_file);  // Close the CSV file before returning
        return;
    }

    // Print headings if it's the first packet
    if (packet_len == 0) {
        fprintf(csv_file, "Source IP,Destination IP,ICMP Type,ICMP Code,ICMP Checksum,ICMP Identifier,ICMP Sequence Number,Packet Size,Timestamp\n");
        fprintf(txt_file, "Timestamp | Source IP | Destination IP | ICMP Type | ICMP Code | ICMP Checksum | ICMP Identifier | ICMP Sequence Number | Packet Size\n");
    }

    // Get current timestamp
    time_t rawtime;
    struct tm *timeinfo;
    char timestamp[20]; // Assuming timestamp will fit in 20 characters
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d%H%M%S", timeinfo);

    // Print packet information to CSV file
    fprintf(csv_file, "%s,%s,%u,%u,%u,%u,%u,%zu,%s\n", source_ip, dest_ip, icmp_header->type, icmp_header->code, checksum, id, sequence, packet_len, timestamp);

    // Print packet information to text file
    fprintf(txt_file, "%s | %s | %s | %u | %u | %u | %u | %u | %zu\n", timestamp, source_ip, dest_ip, icmp_header->type, icmp_header->code, checksum, id, sequence, packet_len);

    // Close the files
    fclose(csv_file);
    fclose(txt_file);

    // Print packet information to console
    printf("Source IP: %s\n", source_ip);
    printf("Destination IP: %s\n", dest_ip);
    printf("ICMP Type: %u\n", icmp_header->type);
    printf("ICMP Code: %u\n", icmp_header->code);
    printf("ICMP Checksum: %u\n", checksum);
    printf("ICMP Identifier: %u\n", id);
    printf("ICMP Sequence Number: %u\n", sequence);
    printf("Packet Size: %zu\n", packet_len);
    printf("Timestamp: %s\n", timestamp);
    printf("\n");
}

