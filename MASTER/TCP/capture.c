#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include "custom_algorithm.h"

FILE *data_txt_file;
FILE *data_csv_file;
pcap_dumper_t *dumper = NULL;
unsigned int packet_number = 0;
	
#define MAX_CLASSIFICATION_SIZE 173000
volatile sig_atomic_t is_interrupted = 0;
int headings_printed = 0;

void handle_interrupt(int signo) {
    is_interrupted = 1;
    if (dumper) pcap_dump_close(dumper);
    if (data_txt_file) fclose(data_txt_file);
    if (data_csv_file) fclose(data_csv_file);
    printf("Capture terminated.\n");
    exit(EXIT_SUCCESS);
}

void format_time(struct timeval ts, char *buffer, size_t buffer_size) {
    struct tm *tm_info = localtime(&ts.tv_sec);
    strftime(buffer, buffer_size, "%b %d %Y %H:%M:%S", tm_info);
    snprintf(buffer + strlen(buffer), buffer_size - strlen(buffer), ".%06ld IST", ts.tv_usec);
}
uint16_t calculate_tcp_checksum(struct iphdr *pIph, struct tcphdr *ipPayload) {
    unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl << 2);
    struct tcphdr *tcphdrp = ipPayload;

    sum += (pIph->saddr >> 16) & 0xFFFF;
    sum += (pIph->saddr) & 0xFFFF;
    sum += (pIph->daddr >> 16) & 0xFFFF;
    sum += (pIph->daddr) & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(tcpLen);
    tcphdrp->check = 0;

    unsigned short *ipPayload16 = (unsigned short *)ipPayload;
    while (tcpLen > 1) {
        sum += *ipPayload16++;
        tcpLen -= 2;
    }

    if (tcpLen > 0) {
        sum += ((*ipPayload16) & htons(0xFF00));
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum = ~sum;
    sum = htons((unsigned short)sum);
    tcphdrp->check = (unsigned short)sum;
    return (unsigned short)sum;
}

void packet_handler(const u_char *packet, size_t packet_len, struct pcap_pkthdr *pkthdr) {
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
    size_t ip_header_length = ip_header->ihl * 4;

    if (ip_header->protocol == IPPROTO_TCP) {
        size_t tcp_header_length = tcp_header->doff * 4;
        size_t headers_length = ip_header_length + tcp_header_length;
        size_t payload_length = packet_len - headers_length;

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);

        uint16_t chs = ntohs(tcp_header->check);
        uint8_t ttl = ip_header->ttl;
        char classification[MAX_CLASSIFICATION_SIZE];
        size_t classification_size = sizeof(classification);
        
        printf("TCP packet captured\n");

        custom_algorithm(tcp_header->th_flags, src_ip, ntohs(tcp_header->source), dst_ip, ntohs(tcp_header->dest),ip_header->protocol, pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1000000.0, packet_len,
        classification, classification_size);

        data_csv_file = fopen("packet_data.csv", "a");
        if (!data_csv_file) {
            fprintf(stderr, "Error opening packet data CSV file for writing\n");
            exit(EXIT_FAILURE);
        }
packet_number++;
        if (!headings_printed) {
            fprintf(data_csv_file, "Packet Number,Timestamp,Relative Time,Packet Size,Payload Length,Source IP,Source Port,Destination IP,Destination Port,IP Protocol,TCP Flags,TTL,Src Checksum,Dst Checksum,Validity\n");
            headings_printed = 1;
        }

 char formatted_time[64];
        format_time(pkthdr->ts, formatted_time, sizeof(formatted_time));
        const char *validity = (chs == calculate_tcp_checksum(ip_header, tcp_header)) ? "valid" : "invalid";
        char flag_str[10];
        snprintf(flag_str, sizeof(flag_str), "0x%04X", ntohs(tcp_header->th_flags));

        fprintf(data_csv_file, "%u,%s,%lf,%zu,%zu,%s,%u,%s,%u,%u,%s,%u,0x%04X,0x%04X,%s\n",packet_number,formatted_time,
                pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1000000.0, packet_len, 
                payload_length, src_ip,
                ntohs(tcp_header->source), dst_ip, ntohs(tcp_header->dest), ip_header->protocol,
                flag_str, ttl, chs, calculate_tcp_checksum(ip_header, tcp_header), validity);

        fclose(data_csv_file);

        pcap_dump((u_char *)dumper, pkthdr, packet);
    }
}

int main() {
    int raw_socket;
    struct sockaddr_in saddr;
    socklen_t saddr_len = sizeof(saddr);
    uint8_t packet_buffer[65536];
    char errbuf[PCAP_ERRBUF_SIZE];

    if ((raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
        perror("Error creating raw socket");
        exit(EXIT_FAILURE);
    }

    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65536);
    dumper = pcap_dump_open(handle, "socket_capture.pcap");
    if (!dumper) {
        fprintf(stderr, "Error opening pcap dump file for writing\n");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, handle_interrupt);
    printf("Capture started. Press Ctrl+C to stop.\n");

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

        packet_handler(packet_buffer, packet_size, &pkthdr);
    }

    pcap_dump_close(dumper);
    close(raw_socket);
    printf("Capture terminated.\n");
    return 0;
}
