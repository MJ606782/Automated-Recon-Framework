import socket

# 1. Setup target details
TARGET_IP = "192.168.56.101"  # <-- Double check your Kali IP here
TARGET_PORT = 8000             # This matches the Netcat port we opened

# 2. Create a standard TCP Socket
# AF_INET means IPv4, SOCK_STREAM means TCP
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.settimeout(3.0)  # Stop waiting after 3 seconds if port is dead

try:
    print(f"Attempting a Connect Scan on {TARGET_IP}:{TARGET_PORT}...")
    
    # 3. Attempt the standard OS TCP 3-Way Handshake
    client_socket.connect((TARGET_IP, TARGET_PORT))
    print("[SUCCESS] Port Detection: Port is OPEN!")
    
    # --- NEW: BANNER GRABBING PIECE ---
    print("Sending HTTP request to grab service banner...")
    
    # Construct a raw HTTP GET request string
    http_request = b"GET / HTTP/1.1\r\nHost: 192.168.56.101\r\n\r\n"
    client_socket.send(http_request)
    
    # Read the first 1024 bytes of the server's response
    response = client_socket.recv(1024).decode(errors='ignore')
    
    print("\n--- GRABBED BANNER INFORMATION ---")
    print(response)
    print("----------------------------------")
    # ----------------------------------
    

except socket.timeout:
    print("[FILTERED] Connection timed out. (Likely a firewall dropped it)")
except ConnectionRefusedError:
    print("[CLOSED] Port Detection: Port is CLOSED!")
finally:
    # 4. Clean up the connection
    client_socket.close()