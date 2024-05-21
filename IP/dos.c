#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 1024
#define MAX_IP_LENGTH 16

// Structure to store IP address and its count
typedef struct {
    char ip[MAX_IP_LENGTH];
    int count;
} IPAddress;

int main() {
    char filename[] = "packet_info.txt"; // CSV file name
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    char line[MAX_LINE_LENGTH];
    IPAddress ipAddresses[100]; // Assuming max 100 unique IP addresses
    int numIPs = 0;
    int threshold = 150; // Adjust threshold as needed

    while (fgets(line, sizeof(line), file)) {
        char *token;
        token = strtok(line, ",");
        token = strtok(NULL, ","); // Skip relative time
        token = strtok(NULL, ","); // Skip frame length
        token = strtok(NULL, ","); // Skip packet size
        char *srcIP = strtok(NULL, ","); // Get source IP address

        // Check if the source IP already exists in the array
        int i;
        int found = 0;
        for (i = 0; i < numIPs; i++) {
            if (strcmp(ipAddresses[i].ip, srcIP) == 0) {
                // Increment count if IP address is found
                ipAddresses[i].count++;
                found = 1;
                break;
            }
        }
        if (!found) {
            // Add new IP address to the array
            strcpy(ipAddresses[numIPs].ip, srcIP);
            ipAddresses[numIPs].count = 1;
            numIPs++;
        }
    }

    // Check if any IP address has more than the threshold count
    for (int i = 0; i < numIPs; i++) {
        if (ipAddresses[i].count > threshold) {
            printf("Possible DoS attack from IP: %s, Request Count: %d\n", ipAddresses[i].ip, ipAddresses[i].count);
        }
    }

    fclose(file);
    return EXIT_SUCCESS;
}

