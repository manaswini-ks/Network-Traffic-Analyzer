#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include "custom_algorithm_udp.h"

void write_to_txt_udp(const char *src_ip, uint16_t src_port, const char *dst_ip, uint16_t dst_port, uint32_t packet_len, const char *classification) {
    FILE *file = fopen("packet_data.txt", "w");
    if (file == NULL) {
        fprintf(stderr, "Error opening packet data file for writing\n");
        return;
    }
    fprintf(file, "Source IP: %s:%u, Destination IP: %s:%u\n", src_ip, src_port, dst_ip, dst_port);
    fprintf(file, "Packet Size: %u bytes\n", packet_len);
    fprintf(file, "Classification: %s\n", classification);
    fclose(file);
}

void custom_algorithm_udp(uint16_t src_port, uint16_t dst_port, const char *src_ip, const char *dst_ip, uint32_t packet_len, char *classification, size_t classification_size) {
    // Initialize classification as benign
    snprintf(classification, classification_size, "Benign");

    // Check source IP for suspicion
    if (strncmp(src_ip, "250.", 4) == 0) {
        // Source IP is suspicious
        snprintf(classification, classification_size, "Suspicious IP");
    }

    // Check packet size for suspicion
    if (packet_len > 2500) {
        // Large packet size, likely to be suspicious
        snprintf(classification, classification_size, "Large Packet Size, Likely Suspicious");
    }

    // Write to text file
    write_to_txt_udp(src_ip, src_port, dst_ip, dst_port, packet_len, classification);

    // Print packet info and benign/malicious info on the terminal
    printf("Packet Info:\n");
    printf("Source IP: %s, Source Port: %u\n", src_ip, src_port);
    printf("Destination IP: %s, Destination Port: %u\n", dst_ip, dst_port);
    printf("Packet Size: %u bytes\n", packet_len);
    printf("Classification: %s\n", classification);
}

