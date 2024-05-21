// icmpattack.h
#ifndef ICMPATTACK_H
#define ICMPATTACK_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h> // Include this for u_char

// Define the signature of the packet_handler function
//void packet_handler(const u_char *packet, size_t packet_len, size_t ip_len);

void detect_dos_attack(const char *filename, int threshold) ;

#endif  // ICMPATTACK_H
