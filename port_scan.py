import socket


TARGET_IP = "192.168.56.101" 
TARGET_PORT = 8000             


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.settimeout(3.0)  

try:
    print(f"Attempting a Connect Scan on {TARGET_IP}:{TARGET_PORT}...")
    
    
    client_socket.connect((TARGET_IP, TARGET_PORT))
    print("[SUCCESS] Port Detection: Port is OPEN!")
    
    
    print("Sending HTTP request to grab service banner")
    
  
    http_request = b"GET / HTTP/1.1\r\nHost: 192.168.56.101\r\n\r\n"
    client_socket.send(http_request)
    
    
    response = client_socket.recv(1024).decode(errors='ignore')
    
    print("\n GRABBED BANNER INFORMATION")
    print(response)
    print("----------------------------------")

    

except socket.timeout:
    print("[FILTERED] Connection timed out. (Likely a firewall dropped it)")
except ConnectionRefusedError:
    print("[CLOSED] Port Detection: Port is CLOSED!")
finally:
    
    client_socket.close()
