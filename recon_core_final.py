from scapy.all import IP, TCP, UDP, ICMP, sr1
import socket
import time
import random


SCAN_TYPE = "SYN"  
TARGET_IP = "192.168.56.101"  # Your Kali VM IP
PORTS_TO_SCAN = [22, 80, 443, 8000, 9999]  

print(f"[*] Initializing Automated Red Team Recon Framework")
print(f"[*] Mode: {SCAN_TYPE} Scan  | Target: {TARGET_IP}")
print("-" * 70)

for port in PORTS_TO_SCAN:
    time.sleep(random.uniform(0.5, 1.2))

    if SCAN_TYPE == "SYN":
        packet = IP(dst=TARGET_IP) / TCP(dport=port, flags="S")
    elif SCAN_TYPE == "ACK":
        packet = IP(dst=TARGET_IP) / TCP(dport=port, flags="A")
    elif SCAN_TYPE == "FIN":
        packet = IP(dst=TARGET_IP) / TCP(dport=port, flags="F")
    elif SCAN_TYPE == "XMAS":
        packet = IP(dst=TARGET_IP) / TCP(dport=port, flags="FPU")
    elif SCAN_TYPE == "UDP":
        packet = IP(dst=TARGET_IP) / UDP(dport=port)

    response = sr1(packet, timeout=1, verbose=False)

  
    if SCAN_TYPE == "UDP":
        if response is None:
            print(f"[+] Port {port:<5} | Status: OPEN or FILTERED")
        elif response.haslayer(ICMP):
            if int(response[ICMP].type) == 3 and int(response[ICMP].code) == 3:
                print(f"[-] Port {port:<5} | Status: CLOSED (ICMP Port Unreachable)")
                
    else: # Handles TCP Scans (SYN, ACK, FIN, XMAS)
        if response and response.haslayer(TCP):
            flags = response[TCP].flags
            ttl = response[IP].ttl
            window = response[TCP].window 
            
            # 1. Processing Stealth SYN Responses
            if SCAN_TYPE == "SYN":
                if flags == "SA" or flags == 0x12:
                    print(f" [+] Port {port:<5} | Status: OPEN")
                   
                    os_guess = "Linux/Unix" if ttl <= 64 else "Windows"
                    if window == 8192 or window == 65535: os_guess = "Windows"
                    print(f" [OS Fingerprint] Matches: {os_guess} (TTL: {ttl}, Window: {window})")
                    
                    
                    try:
                        banner_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        banner_socket.settimeout(2)
                        banner_socket.connect((TARGET_IP, port))
                        
                        if port == 8000 or port == 80: 
                            banner_socket.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
                            banner = banner_socket.recv(1024).decode(errors='ignore').strip()
                            print(f" [HTTP Banner] {banner.splitlines()[0]}")
                        elif port == 22: 
                            banner = banner_socket.recv(1024).decode(errors='ignore').strip()
                            print(f" [SSH Banner] {banner}")
                            
                        banner_socket.close()
                    except Exception:
                        pass
                        
                elif flags == "RA" or flags == 0x14:
                    print(f"[-] Port {port:<5} | Status: CLOSED")
                    
            
            elif SCAN_TYPE in ["FIN", "XMAS"]:
                if flags == "RA" or flags == 0x14:
                    print(f"[-] Port {port:<5} | Status: CLOSED")
                    
            
            elif SCAN_TYPE == "ACK":
                if flags == "R" or flags == 0x14 or flags == "RA":
                    print(f"[+] Port {port:<5} | Status: UNFILTERED (No firewall blockage detected)")

        else:
           
            if SCAN_TYPE in ["FIN", "XMAS"]:
                print(f"[+] Port {port:<5} | Status: OPEN or FILTERED (No response/Dropped)")
            else:
                print(f"[?] Port {port:<5} | Status: FILTERED (Dropped by Firewall rule)")

print("-" * 70)
print("[*] Unified Scan Execution Completed Successfully.")