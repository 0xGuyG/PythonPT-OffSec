#!/bin/python3

"""
Network Security Scanner Script
--------------------------------
This Python3 script performs network scanning and vulnerability assessment tasks.
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
Please install scapy using 'pip install scapy' before running the script.
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
import shutil

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.basicConfig(filename='network_scanner.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s: %(message)s', 
                    datefmt='%Y-%m-%d %H:%M:%S')

def install_enum4linux():
    """
    Checks if Enum4linux is installed and installs it if not found.
    """
    try:
        result = subprocess.run(["enum4linux", "-h"], text=True, capture_output=True, check=False)
        if "enum4linux v" in result.stdout or "enum4linux v" in result.stderr:
            print("Enum4linux is already installed.")
        else:
            print("Enum4linux not found, installing...")
            subprocess.run(["sudo", "apt-get", "install", "-y", "enum4linux"], check=True)
    except Exception as e:
        print(f"An error occurred while installing Enum4linux: {e}")

def install_nmap():
    """
    Checks if Nmap is installed and installs it if not found.
    """
    try:
        result = subprocess.run(["nmap", "-V"], text=True, capture_output=True, check=False)
        if "Nmap version" in result.stdout:
            print("Nmap is already installed.")
        else:
            print("Nmap not found, installing...")
            subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"], check=True)
    except Exception as e:
        print(f"An error occurred while installing Nmap: {e}")

def install_searchsploit():
    """
    Checks if Searchsploit is installed and installs it if not found.
    """
    try:
        result = subprocess.run(["searchsploit", "-v"], text=True, capture_output=True, check=False)
        if "Exploit Database" in result.stdout:
            print("Searchsploit is already installed.")
        else:
            print("Searchsploit not found, installing...")
            subprocess.run(["sudo", "apt-get", "install", "-y", "git"], check=True)
            subprocess.run(["sudo", "git", "clone", "https://github.com/offensive-security/exploitdb.git", "/opt/exploitdb"], check=True)
            subprocess.run(["sudo", "ln", "-sf", "/opt/exploitdb/searchsploit", "/usr/local/bin/searchsploit"], check=True)
    except Exception as e:
        print(f"An error occurred while installing Searchsploit: {e}")

def install_hydra():
    """
    Checks if Hydra is installed and installs it if not found.
    """
    try:
        result = subprocess.run(["hydra", "-h"], text=True, capture_output=True, check=False)
        if "Hydra v" in result.stdout or "Hydra v" in result.stderr:
            print("Hydra is already installed.")
        else:
            print("Hydra not found, installing...")
            subprocess.run(["sudo", "apt-get", "install", "-y", "hydra"], check=True)
    except Exception as e:
        print(f"An error occurred while installing Hydra: {e}")

def install_crunch():
    """
    Checks if Crunch is installed and installs it if not found.
    """
    try:
        result = subprocess.run(["crunch", "-h"], text=True, capture_output=True, check=False)
        if "Crunch can create a wordlist" in result.stdout:
            print("Crunch is already installed.")
        else:
            print("Crunch not found, installing...")
            subprocess.run(["sudo", "apt-get", "install", "-y", "crunch"], check=True)
    except Exception as e:
        print(f"An error occurred while installing Crunch: {e}")

def install_openvpn():
    """
    Checks if OpenVPN is installed and installs it if not found.
    """
    try:
        result = subprocess.run(["openvpn", "--version"], text=True, capture_output=True, check=False)
        if "OpenVPN" in result.stdout or "OpenVPN" in result.stderr:
            print("OpenVPN is already installed.")
        else:
            print("OpenVPN not found, installing...")
            subprocess.run(["sudo", "apt-get", "install", "-y", "openvpn"], check=True)
    except Exception as e:
        print(f"An error occurred while installing OpenVPN: {e}")

def get_live_hosts(ip_input):
    """
    Scans for live hosts in the given IP range or single IP address using ICMP packets.
    Returns a list of live host IPs.
    """
    live_hosts = []
    try:
        if '/' in ip_input:
            # Handle CIDR notation
            for ip in ip_network(ip_input, strict=False).hosts():
                if icmp_scan(str(ip)):
                    live_hosts.append(str(ip))
        elif '-' in ip_input:
            # Handle IP range defined with a hyphen
            start_ip, end_ip = ip_input.split('-')
            start_ip = ip_address(start_ip)
            end_ip = ip_address(end_ip)
            while start_ip <= end_ip:
                if icmp_scan(str(start_ip)):
                    live_hosts.append(str(start_ip))
                start_ip += 1
        else:
            # Check if it's a valid IP address, if not, try to resolve as a domain name
            try:
                ip = ip_address(ip_input)
                if icmp_scan(str(ip)):
                    live_hosts.append(str(ip))
            except ValueError:
                # Handle domain name
                resolved_ip = socket.gethostbyname(ip_input)
                if icmp_scan(resolved_ip):
                    live_hosts.append(resolved_ip)
    except ValueError as ve:
        logging.error(f"Invalid IP address, range, or domain name: {ve}")
        print(f"Invalid IP address, range, or domain name: {ve}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}")
    return live_hosts

def icmp_scan(ip):
    try:
        pkt = IP(dst=str(ip))/ICMP()
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp:
            logging.info(f"Live host found: {ip}")
            print(f"Live host found: {ip}")
            return True
        return False
    except Exception as e:
        logging.error(f"Error scanning {ip}: {e}")
        print(f"Error scanning {ip}: {e}")
        return False

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
    open_ports = []
    for port in range(start_port, end_port + 1):
        pkt = IP(dst=ip)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
            banner = get_banner(ip, port)
            open_ports.append((port, banner))
            logging.info(f"Open port found on {ip}: {port} - Banner: {banner}")
            print(f"Open port found on {ip}: {port} - Banner: {banner}")
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
    except Exception as e:
        logging.error(f"Failed to retrieve banner for {ip} on port {port}: {e}")
        return "No banner or unable to retrieve"

def run_nmap_scan(ip, ports):
    """
    Runs an Nmap scan on the given IP for the specified ports.
    Saves the output to an XML file and returns the filename.
    """
    port_str = ','.join(map(str, ports))
    filename = f"nmap_scan_{ip}.xml"
    subprocess.run(["nmap", "-sV", "--script=vuln", "-p", port_str, "-oX", filename, ip], check=True)
    logging.info(f"Nmap scan completed for {ip}. Results saved in {filename}")
    return filename

def run_searchsploit(nmap_xml_file):
    """
    Uses Searchsploit to find exploits based on an Nmap XML file.
    Writes the output to a file and returns the filename.
    """
    searchsploit_output = f"searchsploit_results_{nmap_xml_file}.txt"
    with open(searchsploit_output, "w") as outfile:
        subprocess.run(["searchsploit", "-j", "--nmap", nmap_xml_file], stdout=outfile, check=True)
    logging.info(f"Searchsploit results saved in {searchsploit_output}")
    return searchsploit_output

def get_user_list():
    """
    Prompts the user to either enter a path to a username list file or input usernames directly.
    If usernames are input directly, they are saved to 'user_list.txt'.
    If a path is provided, 'user_list.txt' will be a copy of the specified file.
    Returns the path 'user_list.txt'.
    """
    choice = input("Do you want to enter a path to a username list or input usernames? (path/input): ").lower()
    output_file = "user_list.txt"

    if choice == "path":
        path = input("Enter the path to the username list: ")
        shutil.copy(path, output_file)
    elif choice == "input":
        print("Enter usernames, one per line. Enter 'done' when finished:")
        user_list = []
        while True:
            user_input = input()
            if user_input == 'done':
                break
            user_list.append(user_input)
        with open(output_file, 'w') as file:
            for username in user_list:
                file.write("%s\n" % username)
    else:
        print("Invalid choice.")
        return get_user_list()
    return output_file

def get_password_list():
    """
    Allows the user to either generate a password list using Crunch or specify a path to a password file.
    If the list is generated using Crunch, it is saved and copied to 'pass_list.txt'.
    If a path is provided, 'pass_list.txt' will be a copy of the specified file.
    Returns the path 'pass_list.txt'.
    """
    choice = input("Do you want to use Crunch to generate a password list, or specify a path to one? (crunch/path): ").lower()
    output_file = "pass_list.txt"
    
    if choice == "crunch":
        min_length = int(input("Enter minimum length of passwords: "))
        max_length = int(input("Enter maximum length of passwords: "))
        charset = input("Enter the character set for the passwords: ")
        crunch_output = "crunch_output.txt"
        subprocess.run(["crunch", str(min_length), str(max_length), charset, "-o", crunch_output], check=True)
        shutil.copy(crunch_output, output_file)
    elif choice == "path":
        path = input("Enter the path to the password list: ")
        shutil.copy(path, output_file)
    else:
        print("Invalid choice.")
        return get_password_list()
    return output_file

def run_enum4linux_scan(ip):
    """
    Runs Enum4linux for SMB service scanning on the specified IP.
    Outputs the results to a file and handles any errors encountered.
    """
    enum4linux_output = f"enum4linux_results_{ip}.txt"
    try:
        print(f"Running Enum4linux on {ip} for SMB service...")
        with open(enum4linux_output, "w") as outfile:
            process = subprocess.run(["enum4linux", "-a", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            outfile.write(process.stdout.decode())
        logging.info(f"Enum4linux scan completed for {ip}. Results saved in {enum4linux_output}")
        print(f"Enum4linux scan results saved to {enum4linux_output}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Enum4linux encountered an error on {ip}: {e}. Check {enum4linux_output} for details")
        print(f"Enum4linux encountered an error: {e}. Command: enum4linux -a {ip}")

def run_hydra(ip, service_port_pairs, user_list_file, pass_list_file):
    """
    Runs Hydra for brute force attacks on the given IP for each service and port.
    Uses specified username and password lists for the attack.
    Accepts a list of tuples (service, port).
    Outputs results and errors to a file.
    """
    for service, port in service_port_pairs:
        hydra_output_file = f"hydra_{service}_{ip}_{port}_output.txt"
        hydra_command = ["hydra", "-L", user_list_file, "-P", pass_list_file, f"{service}://{ip}:{port}"]
        
        with open(hydra_output_file, "w") as outfile:
            print(f"Running Hydra on {ip}:{port} for {service} service...")
            process = subprocess.run(hydra_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            outfile.write(process.stdout.decode())

            if process.returncode != 0:
                logging.info(f"Hydra finished with non-zero exit code on {ip}:{port} for {service}. This might indicate a successful attack.")
                print(f"Hydra may have found credentials. Check {hydra_output_file} for details.")
            else:
                logging.info(f"Hydra did not find credentials on {ip}:{port} for {service}.")
                print(f"No credentials found by Hydra on {ip}:{port} for {service}.")

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
    Known ports for specific services are checked first, followed by banner inspection.
    Returns a list of tuples containing service names and port numbers.
    """
    services = []
    for port, banner in ports_and_banners:
        if port == 22 or "SSH" in banner:
            services.append(("ssh", port))
        elif port == 21 or "FTP" in banner:
            services.append(("ftp", port))
        elif port in [139, 445] or "SMB" in banner or "Microsoft-DS" in banner:
            services.append(("smb", port))
        elif port == 3306 or "MySQL" in banner:
            services.append(("mysql", port))
        elif port == 3389 or "RDP" in banner:
            services.append(("rdp", port))
    return services

def perform_brute_force(host, services, user_list_file, pass_list_file):
    """
    Performs brute force attacks for each detected service on the host.
    Enum4linux is used for SMB services, and Hydra for others.
    """
    # Prepare list of service-port pairs for Hydra, excluding SMB
    service_port_pairs = [(service, port) for service, port in services if service != "smb"]

    # Run Hydra for non-SMB services
    if service_port_pairs:
        run_hydra(host, service_port_pairs, user_list_file, pass_list_file)

    # Run Enum4linux for SMB service
    if any(service == "smb" for service, port in services):
        run_enum4linux_scan(host)
          
def is_linux_system():
    """
    Checks if the current operating system is Linux by looking for a file 
    typically present in Linux distributions.
    Returns True if the system is Linux, False otherwise.
    """
    return os.path.exists('/etc/os-release')

def start_vpn(vpn_config_path):
    """
    Starts an OpenVPN connection using the provided configuration file.
    """
    try:
        subprocess.Popen(["sudo", "openvpn", "--config", vpn_config_path])
        logging.info(f"VPN started successfully using config: {vpn_config_path}")
        print("VPN started in the background.")
    except Exception as e:
        logging.error(f"Failed to start the VPN with config {vpn_config_path}: {e}")
        print("Failed to start the VPN. Check your configuration.")
        sys.exit(1)

def stop_vpn():
    """
    Stops the OpenVPN connection.
    """
    try:
        subprocess.run(["sudo", "killall", "openvpn"], check=True)
        logging.info("VPN stopped successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to stop the VPN: {e}")
        print("Failed to stop the VPN.")

def main():
    """
    Main function that orchestrates the network scanning and vulnerability assessment.
    Requires Linux with root privileges to run.
    """
    # Check if the operating system is Linux
    if not is_linux_system():
        print("This script is designed to run on Linux systems only.")
        sys.exit(1)
      
    # Check for root privileges
    if os.geteuid() != 0:
        print("This script needs to be run with root privileges. Please run it with 'sudo'.")
        sys.exit(1)

    # Install necessary tools
    install_nmap()
    install_searchsploit()
    install_enum4linux()
    install_hydra()
    install_crunch()
    install_openvpn()
  
    # Ask user if they want to use VPN
    use_vpn = input("Would you like to activate a VPN for an external Penetration Test? (yes/no): ").lower()
    if use_vpn == "yes":
        vpn_config_path = input("Enter the path to your OpenVPN configuration file: ")
        start_vpn(vpn_config_path)
      
    # Prompt user for IP address or range to scan
    ip_input = input("Enter an IP address or range to scan: ")
    live_hosts = get_live_hosts(ip_input)

    # Dictionary to store services detected on each host
    all_services = {}

    # Scan each live host
    for host in live_hosts:
        print(f"Scanning {host} for open ports and banners...")
        
        # Get port range from user
        start_port, end_port = get_port_range()
        
        # Scan ports and detect services
        ports_and_banners = scan_ports(host, start_port, end_port)

        if not ports_and_banners:
            print(f"No open ports found on {host}.")
            continue

        # Detect services based on ports and banners
        services = detect_services(host, ports_and_banners)
        for service, port in services:
            print(f"Detected {service} service on {host}:{port}")

        # Store detected services for the host
        all_services[host] = services
        
        # Run Nmap vulnerability scan
        print(f"Running Nmap vulnerability scan on {host}...")
        nmap_ports = [port for port, banner in ports_and_banners]
        nmap_scan_file = run_nmap_scan(host, nmap_ports)
        print(f"Nmap scan results saved in {nmap_scan_file}")

        # Process Nmap results with Searchsploit
        print(f"Searching for exploits for {host} based on Nmap results...")
        searchsploit_output_file = run_searchsploit(nmap_scan_file)
        print(f"Searchsploit results saved in {searchsploit_output_file}")
      
    # Ask user if they want to perform brute force attacks
    brute_force = input("Would you like to perform brute force attacks on the detected services? (yes/no): ").lower()
    if brute_force == "yes":
        # Get user and password lists for brute force
        user_list_file = get_user_list()
        pass_list_file = get_password_list()

        # Perform brute force attacks on each service for each host
        for host, services in all_services.items():
          if services:
              perform_brute_force(host, services, user_list_file, pass_list_file)
      # Stop VPN if it was started
    if use_vpn == "yes":
        stop_vpn()

if __name__ == "__main__":
    main()

#To be integrated later:
#
#Proxychains with Tor: 
#Ensure tools like Nmap, Hydra, and Enum4linux are prefixed with 'proxychains' in their respective functions.
#Configure Proxychains
#https://github.com/HackWithSumit/Tor-Proxychains
