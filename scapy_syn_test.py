from scapy.all import IP, TCP, sr1

target_ip = "192.168.56.101"  
target_port = 8000            

print(f"Sending crafted SYN packet to {target_ip}:{target_port}")

ip_layer = IP(dst=target_ip) 
tcp_layer = TCP(dport=target_port, flags="S") 

crafted_packet = ip_layer / tcp_layer 

response = sr1(crafted_packet, timeout=2, verbose=False)

if response:
    if response.haslayer(TCP):
        received_flags = response[TCP].flags
        print(f"[+] Response received! Raw flags: {received_flags}")
        
        if received_flags == "SA" or received_flags == 0x12:
            print("     Analysis: Flag is SYN-ACK. Port is OPEN!")
        elif received_flags == "RA" or received_flags == 0x14:
            print("     Analysis: Flag is RST-ACK. Port is CLOSED!")
else:
    print("[-] No response received. Port is likely FILTERED by a firewall.")
