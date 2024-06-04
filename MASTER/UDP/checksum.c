// checksum.c
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>

uint16_t calculate_checksum(uint16_t *buf, int nwords) {
    uint32_t sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

int validate_udp_checksum(struct iphdr *ip_header, struct udphdr *udp_header, uint8_t *payload, int payload_size) {
    uint16_t calculated_chksum;
    uint32_t sum = 0;
    uint16_t *p;

    // Pseudo-header addition
    sum += (ip_header->saddr >> 16) & 0xFFFF;
    sum += (ip_header->saddr) & 0xFFFF;
    sum += (ip_header->daddr >> 16) & 0xFFFF;
    sum += (ip_header->daddr) & 0xFFFF;
    sum += htons(ip_header->protocol);
    sum += udp_header->len;

    // UDP header and data
    udp_header->check = 0; // Set checksum to zero for calculation
    p = (uint16_t *)udp_header;
    for (int i = 0; i < sizeof(struct udphdr) / 2; i++, p++) {
        sum += *p;
    }
    p = (uint16_t *)payload;
    for (int i = 0; i < payload_size / 2; i++, p++) {
        sum += *p;
    }

    // If payload_size is odd, add the last byte
    if (payload_size & 1) {
        sum += ((*((uint8_t *)p)) & 0xFF) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    calculated_chksum = ~sum;

    return (calculated_chksum == ntohs(udp_header->check)) ? 1 : 0;
}

