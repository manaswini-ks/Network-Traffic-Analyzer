
#ifndef CUSTOM_ALGORITHM_H
#define CUSTOM_ALGORITHM_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

// Assume you have a CSV file opened in the main code
extern FILE *csv_file;

void custom_algorithm(uint8_t tcp_flags, const char *src_ip, uint16_t src_port, const char *dst_ip, uint16_t dst_port, uint8_t ip_proto, uint8_t ttl, double time_relative, uint32_t frame_len, char *classification, size_t classification_size);

#endif  // CUSTOM_ALGORITHM_H

