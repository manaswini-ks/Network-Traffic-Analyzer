#ifndef CUSTOM_ALGORITHM_H
#define CUSTOM_ALGORITHM_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>


void custom_algorithm_udp(uint16_t src_port, uint16_t dst_port, const char *src_ip, const char *dst_ip, uint32_t packet_len, char *classification, size_t classification_size);

#endif  // CUSTOM_ALGORITHM_H

