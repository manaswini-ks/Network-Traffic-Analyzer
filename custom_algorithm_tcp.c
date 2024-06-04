#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include "custom_algorithm_tcp.h"


/*void write_to_txt(const char *src_ip, uint16_t src_port, const char *dst_ip, uint16_t dst_port, uint8_t ip_proto, uint8_t tcp_flags, double time_relative, uint32_t frame_len, const char *classification)
{
    FILE *file = fopen("packet_data.txt", "w");
    if (file == NULL)
    {
        fprintf(stderr, "Error opening packet data file for writing\n");
        return;
    }
    fprintf(file, "Source IP: %s:%u, Destination IP: %s:%u, IP Protocol: %u\n", src_ip, src_port, dst_ip, dst_port, ip_proto);
    fprintf(file, "Relative Time: %lf, Frame Length: %u, Packet Size: %u bytes\n", time_relative, frame_len, frame_len);
    fprintf(file, "Classification: %s\n", classification);
    fclose(file);
}*/
void write_to_txt(const char *src_ip, uint16_t src_port, const char *dst_ip, uint16_t dst_port, uint8_t ip_proto, uint8_t ttl, uint8_t tcp_flags, double time_relative, uint32_t frame_len, const char *classification)
{
    FILE *file = fopen("packet_data.txt", "a");  // Change "w" to "a" for appending instead of rewriting the whole file.
    if (file == NULL) {
        fprintf(stderr, "Error opening packet data file for writing\n");
        return;
    }
    fprintf(file, "Source IP: %s:%u, Destination IP: %s:%u, IP Protocol: %u, TTL: %u\n", src_ip, src_port, dst_ip, dst_port, ip_proto, ttl);
    fprintf(file, "Relative Time: %lf, Frame Length: %u, Packet Size: %u bytes\n", time_relative, frame_len, frame_len);
    fprintf(file, "Classification: %s\n", classification);
    fclose(file);
}

void custom_algorithm_tcp(uint8_t tcp_flags, const char *src_ip, uint16_t src_port, const char *dst_ip, uint16_t dst_port, uint8_t ip_proto, uint8_t ttl, double time_relative, uint32_t frame_len, char *classification, size_t classification_size)
{
    // Initialize classification as benign
    snprintf(classification, classification_size, "Benign");

    // Check for RST flag
    if (tcp_flags & TH_RST)
    {
        // Packet is potentially malicious
        snprintf(classification, classification_size, "Potentially Malicious");

        /*// Send email alert for potentially malicious packet
        char subject[100];
        char body[200];
        snprintf(subject, sizeof(subject), "Potential Malicious Packet from %s", src_ip);
        snprintf(body, sizeof(body), "A potentially malicious packet was detected:\nSource IP: %s\nSource Port: %u\nDestination IP: %s\nDestination Port: %u\nFrame Length: %u", src_ip, src_port, dst_ip, dst_port, frame_len);
        send_email_alert(subject, body);*/
    }

    // Check source IP for suspicion
    if (strncmp(src_ip, "250.", 4) == 0)
    {
        // Source IP is suspicious
        snprintf(classification, classification_size, "Suspicious IP");
	/*
        // Send email alert for suspicious IP
        char subject[100];
        char body[200];
        snprintf(subject, sizeof(subject), "Suspicious IP Detected: %s", src_ip);
        snprintf(body, sizeof(body), "A packet from a suspicious IP was detected:\nSource IP: %s\nSource Port: %u\nDestination IP: %s\nDestination Port: %u\nFrame Length: %u", src_ip, src_port, dst_ip, dst_port, frame_len);
        send_email_alert(subject, body);*/
    }

    // Check packet size for suspicion
    if (frame_len > 2500)
    {
        // Large packet size, likely to be suspicious
        snprintf(classification, classification_size, "Large Packet Size, Likely Suspicious");
	/*
        // Send email alert for large packet size
        char subject[100];
        char body[200];
        snprintf(subject, sizeof(subject), "Large Packet Size Detected from %s", src_ip);
        snprintf(body, sizeof(body), "A packet with a large size was detected:\nSource IP: %s\nSource Port: %u\nDestination IP: %s\nDestination Port: %u\nFrame Length: %u", src_ip, src_port, dst_ip, dst_port, frame_len);*/
    }

    // Write to text file
    write_to_txt(src_ip, src_port, dst_ip, dst_port, ip_proto, ttl, tcp_flags, time_relative, frame_len, classification);


    // Print packet info and benign/malicious info on the terminal
    printf("Packet Info:\n");
    printf("Source IP: %s, Source Port: %u\n", src_ip, src_port);
    printf("Destination IP: %s, Destination Port: %u\n", dst_ip, dst_port);
    printf("IP Protocol: %u\n", ip_proto);
    printf("Relative Time: %lf, Frame Length: %u, Packet Size: %u bytes\n", time_relative, frame_len, frame_len);
    printf("Classification: %s\n", classification);
}

