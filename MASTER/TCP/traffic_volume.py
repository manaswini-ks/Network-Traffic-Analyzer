import re
import matplotlib.pyplot as plt

# Function to read and plot data
def plot_traffic_volume():
    # Initialize lists to store timestamp and traffic volume
    timestamps = []
    traffic_volumes = []

    # Create a plot
    plt.figure()

    while True:
        # Open the file to read packet data
        with open('packet_data.txt', 'r') as file:
            total_volume = 0
            for line in file:
                # Skip lines that do not start with "Relative Time:"
                if not line.startswith('Relative Time:'):
                    continue

                # Parse the line to extract timestamp and packet size
                parts = line.split(',')
                if len(parts) < 3:
                    # Skip lines with incorrect format
                    continue

                # Extract timestamp
                timestamp = float(parts[0].split(':')[1].strip())

                # Extract packet size and convert it to an integer
                packet_size_str = parts[2].split(':')[1].strip()
                packet_size = int(re.search(r'\d+', packet_size_str).group())

                # Accumulate the packet size to calculate the traffic volume
                total_volume += packet_size

            # Append the timestamp and traffic volume to the lists
            timestamps.append(timestamp)
            traffic_volumes.append(total_volume)

        # Clear the previous plot
        plt.clf()

        # Plot traffic volume versus time
        plt.plot(timestamps, traffic_volumes, 'b-')
        plt.xlabel('Time')
        plt.ylabel('Traffic Volume (bytes)')
        plt.title('Traffic Volume vs. Time')
        plt.draw()
        plt.pause(0.01)  # Pause to allow the plot to update

# Call the function to plot traffic volume
plot_traffic_volume()

