#!/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from ipaddress import ip_address, ip_network
import subprocess
import sys

def install_nmap():
    try:
        subprocess.run(["nmap", "-V"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Nmap not found, installing...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"], check=True)

def install_searchsploit():
    try:
        subprocess.run(["searchsploit", "-v"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Searchsploit not found, installing...")
        subprocess.run(["sudo", "git", "clone", "https://github.com/offensive-security/exploitdb.git", "/opt/exploitdb"], check=True)
        subprocess.run(["sudo", "ln", "-sf", "/opt/exploitdb/searchsploit", "/usr/local/bin/searchsploit"], check=True)

def get_live_hosts(ip_input):
    live_hosts = []
    try:
        # Check if it's a single IP
        ip = ip_address(ip_input)
        pkt = IP(dst=str(ip))/ICMP()
        resp = sr1(pkt, timeout=2, verbose=0)
        if resp:
            live_hosts.append(str(ip))
    except ValueError:
        # If not a single IP, treat it as an IP range
        for ip in ip_network(ip_input).hosts():
            pkt = IP(dst=str(ip))/ICMP()
            resp = sr1(pkt, timeout=2, verbose=0)
            if resp:
                live_hosts.append(str(ip))
    return live_hosts
    
def get_banner(ip, port, timeout=2):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        # Clean up the banner string
        banner = re.sub(r'[\r\n]', ' ', banner)
        return banner
    except:
        return "No banner or unable to retrieve"
        
def scan_ports(ip):
    open_ports = []
    for port in range(1, 65534):
        pkt = IP(dst=ip)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
            # Port is open, try to grab the banner
            banner = get_banner(ip, port)
            open_ports.append((port, banner))
    return open_ports

def run_nmap_scan(ip, ports):
    port_str = ','.join(map(str, ports))
    filename = f"nmap_scan_{ip}.xml"
    subprocess.run(["nmap", "-sV", "--script=vuln", "-p", port_str, "-oX", filename, ip], check=True)
    return filename

def run_searchsploit(nmap_xml_file):
    searchsploit_output = f"searchsploit_results_{nmap_xml_file}.txt"
    with open(searchsploit_output, "w") as outfile:
        subprocess.run(["searchsploit", "-j", "--nmap", nmap_xml_file], stdout=outfile, check=True)
    return searchsploit_output

def main():
     # Check if running as root
    if os.geteuid() != 0:
        print("This script needs to be run with root privileges. Please run it with 'sudo'.")
        sys.exit(1)
    
    install_nmap()
    install_searchsploit()

    ip_input = input("Enter an IP address or range to scan (e.g., 192.168.1.1 or 192.168.1.0/24): ")
    live_hosts = get_live_hosts(ip_input)
    print("Live Hosts:")
    for host in live_hosts:
        print(f"Scanning {host} for open ports and banners...")
        ports_and_banners = scan_ports(host)
        if ports_and_banners:
            for port, banner in ports_and_banners:
                print(f"Host {host}, Port {port}: {banner}")
            print(f"Running Nmap scan on {host} for specific ports...")
            open_ports = [port for port, _ in ports_and_banners]
            nmap_file = run_nmap_scan(host, open_ports)
            print(f"Nmap scan results saved to {nmap_file}")

            print(f"Running Searchsploit for Nmap results...")
            searchsploit_file = run_searchsploit(nmap_file)
            print(f"Searchsploit results saved to {searchsploit_file}")
        else:
            print(f"No open ports found on {host}.")

if __name__ == "__main__":
    main()

