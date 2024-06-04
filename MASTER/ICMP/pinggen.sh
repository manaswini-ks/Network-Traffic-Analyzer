#!/bin/bash

# Script to perform a continuous ping test with random packet sizes

# Infinite loop until Ctrl+C is pressed
while true; do
    # Generate a random packet size between 64 and 1500 bytes
    size=$(shuf -i 64-1500 -n 1)

    # Perform ping test with random packet size
    ping -c 1 -s $size 10.0.2.15

    # Sleep for a short interval before the next iteration (optional)
   #sleep 0.5
done

