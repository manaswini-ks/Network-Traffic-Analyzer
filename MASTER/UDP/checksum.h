// checksum.h
#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <netinet/ip.h>
#include <netinet/udp.h>

int validate_udp_checksum(struct iphdr *ip_header, struct udphdr *udp_header, uint8_t *payload, int payload_size);
uint16_t calculate_checksum(uint16_t *buf, int nwords);
#endif

