import threading
from scapy.all import IP, ICMP, TCP, sr1, send, sniff
import ipaddress

def ping_host(ip, results):
    pkt = IP(dst=str(ip))/ICMP()     
    reply = sr1(pkt, timeout=1, verbose=0)
    if reply:
        results.append(str(ip))

def ping_sweep(subnet):
    results = []
    threads = []
    for ip in ipaddress.IPv4Network(subnet, strict=False).hosts():
        t = threading.Thread(target=ping_host, args=(ip, results))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return results

def syn_scan(ip, port):
    pkt = IP(dst=ip)/TCP(dport=port, flags='S')
    resp = sr1(pkt, timeout=1, verbose=0)
    if resp and resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:
            return "open"
        elif resp[TCP].flags == 0x14:
            return "closed"
    return "Filtered"

def packet_sniffer(filter_exp):
    sniff(filter=filter_exp, prn=lambda x: x.summary(), count=10)

#Menu
if __name__ == "__main__":
    while True:
        print("---- MINI SCAPY TOOLKIT ----")
        print("1. Ping Sweep")
        print("2. TCP SYN Scan")
        print("3. Packet Sniffer")
        print("4. Exit")
        choice = input("Enter your choice (1-4): ")
        
        if choice == "1":
            subnet = input("Enter subnet (e.g., 192.168.1.0/24): ")
            live_hosts = ping_sweep(subnet)
            print("\nLive Hosts:")
            for host in live_hosts:
                print(host)
        
        elif choice == '2':
            ip = input("Enter the target IP address : ")
            port = int(input("Enter the target port number : "))
            status = syn_scan(ip, port)
            print(f"Port {port} on {ip} is {status}")
       
        elif choice == '3':
            filter_exp = input("Enter the filter (e.g., 'tcp', 'udp', 'icmp') : ")    
            packet_sniffer(filter_exp)
        
        elif choice == '4':
            print("Exiting...")
            break
       
        else:
            print("Invalid choice. Please try again.")