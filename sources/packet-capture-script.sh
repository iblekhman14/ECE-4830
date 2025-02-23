#!/bin/bash

# Configuration
DESTINATION_IP="10.10.20.200"
DESTINATION_PORT="5555"  # Choose an appropriate port
INTERFACE="eth0"        # Change this to match your network interface
FILTER="not port 5555"  # Avoid capturing our forwarded traffic

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Check if tcpdump is installed
if ! command -v tcpdump &> /dev/null; then
    echo "tcpdump not found. Installing..."
    apt-get update && apt-get install -y tcpdump
fi

# Check if netcat is installed
if ! command -v nc &> /dev/null; then
    echo "netcat not found. Installing..."
    apt-get update && apt-get install -y netcat
fi

# Function to handle cleanup on script exit
cleanup() {
    echo "Cleaning up..."
    kill $TCPDUMP_PID 2>/dev/null
    exit 0
}

# Set trap for cleanup
trap cleanup SIGINT SIGTERM

# Start packet capture and forwarding
echo "Starting packet capture on $INTERFACE and forwarding to $DESTINATION_IP:$DESTINATION_PORT"
tcpdump -i "$INTERFACE" -U -w - "$FILTER" 2>/dev/null | \
    nc "$DESTINATION_IP" "$DESTINATION_PORT" &

TCPDUMP_PID=$!

# Log start time and basic info
echo "Capture started at $(date)"
echo "Monitoring interface: $INTERFACE"
echo "Forwarding to: $DESTINATION_IP:$DESTINATION_PORT"

# Keep script running and monitor status
while true; do
    if ! kill -0 $TCPDUMP_PID 2>/dev/null; then
        echo "Capture process died, restarting..."
        tcpdump -i "$INTERFACE" -U -w - "$FILTER" 2>/dev/null | \
            nc "$DESTINATION_IP" "$DESTINATION_PORT" &
        TCPDUMP_PID=$!
    fi
    sleep 10
done
