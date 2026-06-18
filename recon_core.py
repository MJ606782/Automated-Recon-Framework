from scapy.all import IP, TCP, sr1
import socket


target_ip = "192.168.56.101" 
ports_to_scan = [22, 80, 443, 8000, 9999] 

print(f"[*] Initializing Automated Recon Framework on {target_ip}")
print("-" * 55)


for port in ports_to_scan:
    

    packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
    response = sr1(packet, timeout=1, verbose=False)
    
    
    if response and response.haslayer(TCP):
        flags = response[TCP].flags
        
        
        if flags == "SA" or flags == 0x12:
            print(f"[+] Port {port:<5} | Status: OPEN (Stealth SYN Detected)")
            if response.haslayer(IP):
                ttl_value = response[IP].ttl
                
                
                if ttl_value <= 64:
                    os_guess = "Linux/Unix"
                elif ttl_value <= 128:
                    os_guess = "Windows"
                else:
                    os_guess = "Network Device (Cisco/Embedded)"
                
                print(f"    [OS Inference] Target OS signature matches: {os_guess} (TTL: {ttl_value})")
            
            
            if port == 8000:
                try:
                    banner_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    banner_socket.settimeout(2)
                    banner_socket.connect((target_ip, port))
                    banner_socket.send(b"GET / HTTP/1.1\r\nHost: 192.168.56.101\r\n\r\n")
                    
                    banner = banner_socket.recv(1024).decode(errors='ignore').strip()
                   
                    print(f"   Banner Info: {banner.splitlines()[0] if banner else 'No header returned'}")
                    banner_socket.close()
                except Exception:
                    print("    Banner Info: Connection closed before data extraction.")
                    
        
        elif flags == "RA" or flags == 0x14:
            print(f"[-] Port {port:<5} | Status: CLOSED")
            
    
    else:
        print(f"[?] Port {port:<5} | Status: FILTERED (Firewall Active / Timeout)")

print("-" * 55)
print("[*] Scan complete.")
