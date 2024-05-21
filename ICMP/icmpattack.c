#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IP_COUNT 100 // Adjust this based on your needs

void detect_dos_attack(const char *filename, int threshold) {
    FILE *csv_file = fopen(filename, "r");
    if (csv_file == NULL) {
        perror("Error opening CSV file");
        exit(EXIT_FAILURE);
    }

    char line[1024];
    int packets_in_second = 0;
    double prev_timestamp = 0.0;
    char source_ips[MAX_IP_COUNT][16]; // Assuming IPv4 addresses (xxx.xxx.xxx.xxx)
    int ip_count = 0;

    FILE *output_file = fopen("dos_attack_info.txt", "w");
    if (output_file == NULL) {
        perror("Error opening output file");
        fclose(csv_file);
        exit(EXIT_FAILURE);
    }

    while (fgets(line, sizeof(line), csv_file)) {
        // Tokenize the line
        char *token;
        token = strtok(line, ",");
        if (token == NULL) {
            continue; // Skip empty lines
        }
        double timestamp = atof(token);

        // Check if the timestamp differs from the previous one
        if (timestamp != prev_timestamp) {
            // Check if packets in the last second exceed the threshold
            if (packets_in_second > threshold) {
                fprintf(output_file, "Potential DoS attack detected: More than %d packets in one second\n", threshold);
                // Write the source IPs that caused the attack to the output file
                for (int i = 0; i < ip_count; i++) {
                    fprintf(output_file, "Source IP: %s\n", source_ips[i]);
                }
                fprintf(output_file, "\n"); // Add a newline for clarity
            }
            // Reset packet count and IP count for the new second
            packets_in_second = 0;
            ip_count = 0;
            // Update the previous timestamp
            prev_timestamp = timestamp;
        }

        // Increment packet count for the current second
        packets_in_second++;

        // Extract source IP
        token = strtok(NULL, ",");
        if (token != NULL) {
            strcpy(source_ips[ip_count], token);
            ip_count++;
        }
    }

    // Check if the last second exceeds the threshold
    if (packets_in_second > threshold) {
        fprintf(output_file, "Potential DoS attack detected: More than %d packets in one second\n", threshold);
        // Write the source IPs that caused the attack to the output file
        for (int i = 0; i < ip_count; i++) {
            fprintf(output_file, "Source IP: %s\n", source_ips[i]);
        }
    }

    fclose(csv_file);
    fclose(output_file);
}

