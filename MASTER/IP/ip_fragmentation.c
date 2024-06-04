#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ID_COUNT 10000  // Maximum number of ID values to track

// Structure to store ID counts
struct IDCounter {
    int id;
    int count;
};

int main() {
    FILE *input_file;
    char line[1024];
    struct IDCounter id_counters[MAX_ID_COUNT];
    int num_counters = 0;

    // Open the input file
    input_file = fopen("packet_info.txt", "r");
    if (input_file == NULL) {
        perror("Error opening input file");
        return EXIT_FAILURE;
    }

    // Read packet information from the CSV file and count occurrences of each ID
    while (fgets(line, sizeof(line), input_file)) {
        // Tokenize the line to extract the 11th field (ID)
        char *token = strtok(line, ",");
        for (int i = 1; i < 11; i++) {
            token = strtok(NULL, ",");
        }
        int id = atoi(token);

        // Ignore ID 0 (undefined or empty value)
        if (id == 0) {
            continue;
        }

        // Check if ID already exists in the counters array
        int i;
        for (i = 0; i < num_counters; i++) {
            if (id_counters[i].id == id) {
                // Increment the count for existing ID
                id_counters[i].count++;
                break;
            }
        }

        // If ID is not found, add it to the counters array
        if (i == num_counters) {
            if (num_counters < MAX_ID_COUNT) {
                id_counters[num_counters].id = id;
                id_counters[num_counters].count = 1;
                num_counters++;
            } else {
                fprintf(stderr, "Exceeded maximum number of ID counters\n");
                break;
            }
        }
    }

    // Check if any ID appears more than once and generate an alert
    int alert_generated = 0;
    for (int i = 0; i < num_counters; i++) {
        if (id_counters[i].count > 2) {
            printf("Alert: ID %d appears more than once (Count: %d)\nExcessive Fragmentation, Potential Attack\n", id_counters[i].id, id_counters[i].count);
            alert_generated = 1;
        }
    }

    // If no alerts were generated, indicate that no excessive fragmentation was detected
    if (!alert_generated) {
        printf("No excessive fragmentation detected.\n");
    }

    // Close the input file
    fclose(input_file);

    return EXIT_SUCCESS;
}

