import matplotlib.pyplot as plt
import time

# Function to read and plot data
def plot_packet_data():
    # Initialize lists to store packet size and timestamp
    timestamps = []
    packet_sizes = []

    # Create a plot
    plt.figure()

    while True:
        # Open the file to read packet data
        with open('packet_data.txt', 'r') as file:
            for line in file:
                print("Line:", line)  # Debug print statement
                # Skip lines that do not start with "Relative Time:"
                if not line.startswith('Relative Time:'):
                    continue

                # Parse the line to extract timestamp and packet size
                parts = line.split(',')
                print("Parts:", parts)  # Debug print statement
                if len(parts) < 2:
                    # Skip lines with incorrect format
                    continue

                # Extract timestamp and packet size
                timestamp = float(parts[0].split(':')[1].strip())
                packet_size = int(parts[1].split(':')[1].strip())

                # Append the data to the lists
                timestamps.append(timestamp)
                packet_sizes.append(packet_size)

                # Clear the previous plot
                plt.clf()

                # Plot packet size versus time
                plt.plot(timestamps, packet_sizes, 'b-')
                plt.xlabel('Time')
                plt.ylabel('Packet Size (bytes)')
                plt.title('Packet Size vs. Time')
                plt.draw()
                plt.pause(0.01)  # Pause to allow the plot to update

# Call the function to plot data
plot_packet_data()

