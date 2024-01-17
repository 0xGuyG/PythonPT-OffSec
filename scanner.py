#!/bin/python3
import logging
import os
import re
import socket
import subprocess
import sys
from ipaddress import ip_address, ip_network
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def install_enum4linux():
    try:
        subprocess.run(["enum4linux", "-h"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Enum4linux not found, installing...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "enum4linux"], check=True)

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
        subprocess.run(["sudo", "apt-get", "install", "-y", "git"], check=True)
        subprocess.run(["sudo", "git", "clone", "https://github.com/offensive-security/exploitdb.git", "/opt/exploitdb"], check=True)
        subprocess.run(["sudo", "ln", "-sf", "/opt/exploitdb/searchsploit", "/usr/local/bin/searchsploit"], check=True)

def install_hydra():
    try:
        subprocess.run(["hydra", "-h"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Hydra not found, installing...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "hydra"], check=True)

def install_crunch():
    try:
        subprocess.run(["crunch", "-h"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Crunch not found, installing...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "crunch"], check=True)

def get_live_hosts(ip_input):
    live_hosts = []
    try:
        ip = ip_address(ip_input)
        print(f"Scanning {ip} for live hosts...")
        pkt = IP(dst=str(ip))/ICMP()
        resp = sr1(pkt, timeout=2, verbose=0)
        if resp:
            print(f"Live host found: {ip}")
            live_hosts.append(str(ip))
    except ValueError:
        for ip in ip_network(ip_input).hosts():
            print(f"Scanning {ip} for live hosts...")
            pkt = IP(dst=str(ip))/ICMP()
            resp = sr1(pkt, timeout=2, verbose=0)
            if resp:
                print(f"Live host found: {ip}")
                live_hosts.append(str(ip))
    return live_hosts

def get_port_range():
    while True:
        try:
            start_port = int(input("Enter the start port (1-65535): "))
            end_port = int(input("Enter the end port (1-65535): "))
            if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                return start_port, end_port
            else:
                print("Invalid port range. Please enter a valid range between 1 and 65535.")
        except ValueError:
            print("Invalid input. Please enter numeric values.")

def scan_ports(ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        print(f"Checking port {port} on {ip}...")
        pkt = IP(dst=ip)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
            banner = get_banner(ip, port)
            print(f"Open port found on {ip}: {port} - Banner: {banner}")
            open_ports.append((port, banner))
    return open_ports

def get_banner(ip, port, timeout=2):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        banner = re.sub(r'[\r\n]', ' ', banner)
        return banner
    except:
        return "No banner or unable to retrieve"

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

def get_user_list():
    choice = input("Do you want to enter a path to a username list or input usernames? (path/input): ").lower()
    if choice == "path":
        return input("Enter the path to the username list: ")
    elif choice == "input":
        return input("Enter usernames separated by commas: ").split(',')
    else:
        print("Invalid choice.")
        return get_user_list()

def get_password_list():
    choice = input("Do you want to use Crunch to generate a password list, or specify a path to one? (crunch/path): ").lower()
    if choice == "crunch":
        min_length = int(input("Enter minimum length of passwords: "))
        max_length = int(input("Enter maximum length of passwords: "))
        charset = input("Enter the character set for the passwords: ")
        output_file = "crunch_output.txt"
        subprocess.run(["crunch", str(min_length), str(max_length), charset, "-o", output_file], check=True)
        return output_file
    elif choice == "path":
        return input("Enter the path to the password list: ")
    else:
        print("Invalid choice.")
        return get_password_list()

def run_enum4linux_scan(ip):
    print(f"Running Enum4linux on {ip} for SMB service...")
    enum4linux_output = f"enum4linux_results_{ip}.txt"
    with open(enum4linux_output, "w") as outfile:
        subprocess.run(["enum4linux", "-a", ip], stdout=outfile, check=True)
    print(f"Enum4linux scan results saved to {enum4linux_output}")
    return enum4linux_output

def run_hydra(ip, port, service, user_list_file, pass_list_file):
    print(f"Running Hydra on {ip}:{port} for {service} service...")
    subprocess.run(["hydra", "-L", user_list_file, "-P", pass_list_file, f"{service}://{ip}:{port}"], check=True)

def save_list_to_file(lst, filename):
    with open(filename, 'w') as file:
        for item in lst:
            file.write("%s\n" % item)
    return filename

def detect_services(host, ports_and_banners):
    services = []
    for port, banner in ports_and_banners:
        if "SSH" in banner:
            services.append(("ssh", port))
        elif "FTP" in banner:
            services.append(("ftp", port))
        elif "SMB" in banner or "Microsoft-DS" in banner or port in [139, 445]:
            services.append(("smb", port))
        elif "MySQL" in banner or port == 3306:
            services.append(("mysql", port))
        elif "RDP" in banner or port == 3389:
            services.append(("rdp", port))
    return services

def perform_brute_force(host, services, user_list, pass_list):
    for service, port in services:
        if service == "smb":
            run_enum4linux_scan(host)
        else:
            run_hydra(host, port, service, user_list, pass_list)

def main():
    if os.geteuid() != 0:
        print("This script needs to be run with root privileges. Please run it with 'sudo'.")
        sys.exit(1)

    install_nmap()
    install_searchsploit()
    install_enum4linux()
    install_hydra()
    install_crunch()

    ip_input = input("Enter an IP address or range to scan: ")
    live_hosts = get_live_hosts(ip_input)

    for host in live_hosts:
        print(f"Scanning {host} for open ports and banners...")
        start_port, end_port = get_port_range()
        ports_and_banners = scan_ports(host, start_port, end_port)

        if not ports_and_banners:
            print(f"No open ports found on {host}.")
            continue

        services = detect_services(host, ports_and_banners)
        for service, port in services:
            print(f"Detected {service} service on {host}:{port}")

        if services:
            brute_force = input("Would you like to perform brute force attacks? (yes/no): ").lower()
            if brute_force == "yes":
                user_list = get_user_list()
                pass_list = get_password_list()
                user_list_file = save_list_to_file(user_list, "user_list.txt")
                pass_list_file = save_list_to_file(pass_list, "pass_list.txt")
                run_hydra(host, port, service, user_list_file, pass_list_file)

if __name__ == "__main__":
    main()
