#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>

// Define the private IP address ranges
struct PrivateRange {
    uint32_t start;
    uint32_t end;
};

// Array of private IP address ranges
const struct PrivateRange private_ranges[] = {
    {0x0A000000, 0x0AFFFFFF},   // 10.0.0.0 to 10.255.255.255
    {0xAC100000, 0xAC1FFFFF},   // 172.16.0.0 to 172.31.255.255
    {0xC0A80000, 0xC0A8FFFF}    // 192.168.0.0 to 192.168.255.255
};

int is_private_ip(uint32_t ip) {
    // Convert IP address to network byte order
    ip = htonl(ip);
    
    // Check if the IP address falls within any of the private ranges
    for (int i = 0; i < sizeof(private_ranges) / sizeof(private_ranges[0]); i++) {
        if (ip >= private_ranges[i].start && ip <= private_ranges[i].end) {
            return 1;  // IP address is private
        }
    }
    
    return 0;  // IP address is not private
}

int main() {
    // Open the CSV file
    FILE *file = fopen("packet_info.txt", "r");
    if (!file) {
        perror("Error opening file");
        return 1;
    }
    
    char line[100];
    
    // Read lines from the file and check if the source IP addresses are private
    while (fgets(line, sizeof(line), file)) {
        char src_ip_str[16];
        sscanf(line, "%*[^,],%*[^,],%*[^,],%15[^,]", src_ip_str);
        
        uint32_t src_ip;
        inet_pton(AF_INET, src_ip_str, &src_ip);
        
        if (is_private_ip(src_ip)) {
            printf("%s is a private IP address\n", src_ip_str);
        } 
    }
    
    // Close the file
    fclose(file);

    return 0;
}

