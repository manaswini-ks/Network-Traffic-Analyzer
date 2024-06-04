#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>

volatile sig_atomic_t is_interrupted = 0;
pcap_dumper_t *dumper = NULL;  // Declare pcap dumper globally

void handle_interrupt(int signo) {
    is_interrupted = 1;

    // Close the pcap dump file on interruption
    if (dumper) {
        pcap_dump_close(dumper);
    }

    printf("Capture terminated.\n");
    exit(EXIT_SUCCESS);
}

void packet_handler(const u_char *packet, size_t packet_len, struct pcap_pkthdr *pkthdr, FILE *output_file) {
    // Ethernet header
    struct ethhdr *eth_header = (struct ethhdr *)packet;

    // IP header
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

    // Extract IP header information
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);

    // Extract the "More Fragments" flag from the Fragment Offset field
    int more_fragments = (ntohs(ip_header->frag_off) & IP_MF) != 0;

    // Write packet information to file in CSV format
    fprintf(output_file, "%lf,%u,%zu,%s,%s,%u,%u,%u,%u,%u,%u,%d,%u,%u,%u\n",
            pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1000000.0, // Timestamp
            (unsigned int)pkthdr->caplen, // Frame Length
            packet_len, // Packet Size
            src_ip, // Source IP
            dst_ip, // Destination IP
            ip_header->protocol, // Protocol
            (unsigned int)ip_header->version, // IP Version
            (unsigned int)(ip_header->ihl * 4), // IP Header Length
            (unsigned int)((ip_header->tos & 0xfc) >> 2), // DSCP
            ntohs(ip_header->tot_len), // Total Length
            ntohs(ip_header->id), // Identification
            more_fragments, // More Fragments
            (unsigned int)(ntohs(ip_header->frag_off) & 0x1fff), // Fragment Offset
            (unsigned int)ip_header->ttl, // Time to Live
            (unsigned int)ip_header->check // IP Header Checksum
    );
}



int main() {
    int raw_socket;
    struct sockaddr_in saddr;
    socklen_t saddr_len = sizeof(saddr);
    uint8_t packet_buffer[65536];  // Adjust this size based on your needs
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open a raw socket
    if ((raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
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

    // Open output file for writing packet information
    FILE *output_file = fopen("packet_info.txt", "w");
    if (!output_file) {
        fprintf(stderr, "Error opening output file for writing\n");
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
        packet_handler(packet_buffer, packet_size, &pkthdr, output_file);

        // Write the packet to the pcap dump file
        pcap_dump((u_char *)dumper, &pkthdr, packet_buffer);
    }

    // Close the output file
    fclose(output_file);

    // Close the pcap dump file
    pcap_dump_close(dumper);

    // Close the raw socket
    close(raw_socket);

    printf("Capture terminated.\n");

    return 0;
}

