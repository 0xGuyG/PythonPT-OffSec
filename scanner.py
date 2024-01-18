#!/bin/python3

"""
Network Security Scanner Script
--------------------------------
This script performs network scanning and vulnerability assessment tasks.
It includes functionality to check for live hosts, scan open ports, detect services,
and perform brute force attacks using various tools.

Key Features:
- Scans for live hosts in a given IP range using ICMP packets.
- Performs port scanning to identify open ports on live hosts.
- Detects services running on open ports and attempts to grab banners.
- Utilizes Nmap for detailed port scanning and service detection. Nmap's powerful scanning
  capabilities allow for effective identification of open ports and services running on a target host.
- Integrates Searchsploit with Nmap scan results for automated vulnerability assessment.
  Searchsploit is used to search for known vulnerabilities of the services detected by Nmap,
  aiding in the identification of potential security weaknesses.
- Supports brute force attacks with Hydra for services like SSH, FTP, SMB, MySQL, and RDP.
- Offers options to use custom username and password lists for brute force attacks, either
  by specifying file paths or direct input.

Note:
The script operates with the assumption it runs on linux and requires root privileges to perform certain operations. It should be used responsibly
and legally, ensuring permission is obtained before scanning and testing networks and systems.
"""

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
    """
    Checks if Enum4linux is installed. If not, installs it using apt-get.
    """
    try:
        subprocess.run(["enum4linux", "-h"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Enum4linux not found, installing...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "enum4linux"], check=True)

def install_nmap():
    """
    Checks if Nmap is installed. If not, installs it using apt-get.
    """
    try:
        subprocess.run(["nmap", "-V"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Nmap not found, installing...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"], check=True)

def install_searchsploit():
    """
    Checks if Searchsploit is installed. If not, installs it using git.
    """
    try:
        subprocess.run(["searchsploit", "-v"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Searchsploit not found, installing...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "git"], check=True)
        subprocess.run(["sudo", "git", "clone", "https://github.com/offensive-security/exploitdb.git", "/opt/exploitdb"], check=True)
        subprocess.run(["sudo", "ln", "-sf", "/opt/exploitdb/searchsploit", "/usr/local/bin/searchsploit"], check=True)

def install_hydra():
    """
    Checks if Hydra is installed. If not, installs it using apt-get.
    """
    try:
        subprocess.run(["hydra", "-h"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Hydra not found, installing...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "hydra"], check=True)

def install_crunch():
    """
    Checks if Crunch is installed. If not, installs it using apt-get.
    """
    try:
        subprocess.run(["crunch", "-h"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Crunch not found, installing...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "crunch"], check=True)

def get_live_hosts(ip_input):
    """
    Scans for live hosts in the given IP range or single IP address using ICMP packets.
    Returns a list of live host IPs.
    """
    live_hosts = []
    try:
        ip = ip_address(ip_input)
        print(f"Scanning {ip} for life signs...")
        pkt = IP(dst=str(ip))/ICMP()
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp:
            print(f"Live host found: {ip}")
            live_hosts.append(str(ip))
    except ValueError:
        for ip in ip_network(ip_input).hosts():
            print(f"Scanning {ip} for life signs...")
            pkt = IP(dst=str(ip))/ICMP()
            resp = sr1(pkt, timeout=1, verbose=0)
            if resp:
                print(f"Live host found: {ip}")
                live_hosts.append(str(ip))
    return live_hosts

def get_port_range():
    """
    Prompts the user to enter a valid start and end port range.
    Returns a tuple of start and end ports.
    """
    while True:
        try:
            start_port = int(input("Enter the start port (0-65536): "))
            end_port = int(input("Enter the end port (0-65536): "))
            if 0 <= start_port <= 65536 and 0 <= end_port <= 65536 and start_port <= end_port:
                return start_port, end_port
            else:
                print("Invalid port range. Please enter a valid range between 0 and 65536.")
        except ValueError:
            print("Invalid input. Please enter numeric values.")

def scan_ports(ip, start_port, end_port):
    """
    Scans the given IP address for open ports in the specified range.
    Returns a list of tuples containing open port numbers and their banners.
    """
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
    """
    Attempts to retrieve a banner from the specified IP and port.
    Returns the banner string or a default message if unavailable.
    """
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
    """
    Runs an Nmap scan on the given IP for the specified ports.
    Saves the output to an XML file and returns the filename.
    """
    port_str = ','.join(map(str, ports))
    filename = f"nmap_scan_{ip}.xml"
    subprocess.run(["nmap", "-sV", "--script=vuln", "-p", port_str, "-oX", filename, ip], check=True)
    return filename

def run_searchsploit(nmap_xml_file):
    """
    Uses Searchsploit to find exploits based on an Nmap XML file.
    Writes the output to a file and returns the filename.
    """
    searchsploit_output = f"searchsploit_results_{nmap_xml_file}.txt"
    with open(searchsploit_output, "w") as outfile:
        subprocess.run(["searchsploit", "-j", "--nmap", nmap_xml_file], stdout=outfile, check=True)
    return searchsploit_output

def get_user_list():
    """
    Prompts the user to either enter a path to a username list file or input usernames directly.
    Returns a list of usernames or a string representing the path to the username file.
    """
    choice = input("Do you want to enter a path to a username list or input usernames? (path/input): ").lower()
    if choice == "path":
        return input("Enter the path to the username list: ")
    elif choice == "input":
        print("Enter usernames, one per line. Enter 'done' when finished:")
        user_list = []
        while True:
            user_input = input()
            if user_input == 'done':
                break
            user_list.append(user_input)
        return user_list
    else:
        print("Invalid choice.")
        return get_user_list()

def get_password_list():
    """
    Allows the user to either generate a password list using Crunch or specify a path to a password file.
    Returns the path to the password list file.
    """
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
    """
    Runs Enum4linux for SMB service scanning on the specified IP.
    Outputs the results to a file and returns the filename.
    """
    print(f"Running Enum4linux on {ip} for SMB service...")
    enum4linux_output = f"enum4linux_results_{ip}.txt"
    with open(enum4linux_output, "w") as outfile:
        subprocess.run(["enum4linux", "-a", ip], stdout=outfile, check=True)
    print(f"Enum4linux scan results saved to {enum4linux_output}")
    return enum4linux_output

def run_hydra(ip, port, service, user_list_file, pass_list_file):
    """
    Runs Hydra for brute force attacks on the given IP, port, and service.
    Uses specified username and password lists for the attack.
    """
    print(f"Running Hydra on {ip}:{port} for {service} service...")
    subprocess.run(["hydra", "-L", user_list_file, "-P", pass_list_file, f"{service}://{ip}:{port}"], check=True)

def save_list_to_file(lst, filename):
    """
    Saves a given list to a file, writing each item on a new line.
    Returns the filename.
    """
    with open(filename, 'w') as file:
        for item in lst:
            file.write("%s\n" % item)
    return filename

def detect_services(host, ports_and_banners):
    """
    Detects services running on open ports based on port numbers and banners.
    Returns a list of tuples containing service names and port numbers.
    """
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
    """
    Performs brute force attacks for each detected service on the host.
    Enum4linux is used for SMB services, and Hydra for others.
    """
    for service, port in services:
        if service == "smb":
            run_enum4linux_scan(host)
        else:
            run_hydra(host, port, service, user_list, pass_list)

def main():
    """
    Main function that orchestrates the network scanning and vulnerability assessment.
    Requires root privileges to run.
    """
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


#To be integrated later:
#VPN:
#def start_vpn(vpn_config_path):
#    """
#    Starts an OpenVPN connection using the provided configuration file.
#    """
#    try:
#        subprocess.run(["sudo", "openvpn", "--config", vpn_config_path], check=True)
#    except subprocess.CalledProcessError:
#        print("Failed to start the VPN. Check your configuration.")
#        sys.exit(1)
#
#def stop_vpn():
#    """
#    Stops the OpenVPN connection.
#    """
#    # Stopping OpenVPN can be complex as it might require killing the process.
#    # This could be done based on the process ID or process name.
#    try:
#        subprocess.run(["sudo", "killall", "openvpn"], check=True)
#    except subprocess.CalledProcessError:
#        print("Failed to stop the VPN.")
#
#Into Main function:
#vpn_config_path = input("Enter the path to your OpenVPN configuration file: ")
#    start_vpn(vpn_config_path) #Start VPN at the beginning
#    stop_vpn()  # Disconnect VPN at the end
#
#Proxychains with Tor: Ensure tools like Nmap, Hydra, and Enum4linux are prefixed with 'proxychains' in their respective functions.
#Configure Proxychains
