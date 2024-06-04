#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 1024

int main() {
    char filename[] = "packet_info.txt"; // CSV file name
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    char line[MAX_LINE_LENGTH];
    double timestamp;
    int packetsInSecond = 0;
    int threshold = 100; // Adjust threshold as needed

    while (fgets(line, sizeof(line), file)) {
        char *token;
        token = strtok(line, ",");
        timestamp = atof(token); // Get timestamp

        // Check if the timestamp differs from the previous one
        static double prevTimestamp = 0.0;
        if (timestamp != prevTimestamp) {
            // Check if packets in the last second exceed the threshold
            if (packetsInSecond > threshold) {
                printf("Potential DoS attack detected: More than %d packets in one second\n", threshold);
            }
            // Reset packet count for the new second
            packetsInSecond = 0;
            // Update the previous timestamp
            prevTimestamp = timestamp;
        }

        // Increment packet count for the current second
        packetsInSecond++;
    }

    // Check if the last second exceeds the threshold
    if (packetsInSecond > threshold) {
        printf("Potential DoS attack detected: More than %d packets in one second\n", threshold);
    }

    fclose(file);
    return EXIT_SUCCESS;
}

