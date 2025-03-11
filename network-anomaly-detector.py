from pyVNC.Client import Client
import time

# Create VNC client instance
vnc = Client(host="127.0.0.1",
             password=None,  # Set to None for no password or provide as string
             port=5900,      # TightVNC usually runs on port 5900 by default
             depth=32,
             fast=True,      # Using fast encoding for better compatibility
             shared=True,
             gui=False,      # Set to True if you want to see the GUI
             array=True)     # Set to True to get screen as numpy array
             
# Start the client
print("Starting VNC client...")
vnc.start()

# Wait for connection to establish and protocol to initialize
print("Waiting for connection to establish...")
time.sleep(2)  # Give it some time to connect

# Check if connection is established
if hasattr(vnc.screen, 'protocol') and vnc.screen.protocol is not None:
    print("Connected successfully!")
    
    try:
        # Interact with the remote system
        print("Sending key 'a'...")
        vnc.send_key("a")
        time.sleep(0.5)
        
        print("Sending left mouse click at (200, 200)...")
        vnc.send_mouse("Left", (200, 200))
        time.sleep(0.5)
        
        print("Sending right mouse click at (200, 200)...")
        vnc.send_mouse("Right", (200, 200))
        time.sleep(0.5)
        
        # Get screen capture
        print("Getting screen capture...")
        screen = vnc.screen.get_array()
        print(f"Screen shape: {screen.shape if screen is not None else 'Not available'}")
        
    except Exception as e:
        print(f"Error while sending events: {e}")
else:
    print("Connection failed or protocol not initialized")

# Close the connection
print("Closing connection...")
vnc.join()
