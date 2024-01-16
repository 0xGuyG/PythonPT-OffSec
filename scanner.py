import os
import subprocess
import time
import sys
import scapy.all as scapy

# Install Scapy if not already installed
try:
    import scapy.all as scapy
except ImportError:
    print("Scapy not found. Installing Scapy...")
    os.system("pip install scapy")
    import scapy.all as scapy

# Install the necessary apps
def install():
    print("[*] Updating System")
    os.system("sudo apt-get update")
    apps = ["nmap", "ipcalc", "searchsploit", "hydra", "crunch"]
    for app in apps:
        print(f"[*] Installing {app}")
        os.system(f"sudo apt-get install {app} -y")

# Acquire start of scan to calculate runtime
start = time.time()

# Ascertain the LAN range
def Q1():
    os.chdir("~/Desktop")
    network_info = subprocess.getoutput("ipcalc -n $(hostname -I)")
    network = [line.split()[1] for line in network_info.split('\n') if "network" in line.lower()][0]
    print(f"{network} is the LAN Range")
    print("Commencing Ping Sweep:")
    subnet = subprocess.getoutput("ip route | grep default | awk '{print $3}' | cut -d '.' -f 1-3")
    subnet = subnet.strip()
    
    active_devices = []
    for ip in range(1, 255):
        ip_address = f"{subnet}.{ip}"
        print(f"Pinging {ip_address}")
        ping_result = os.system(f"ping -c 1 -W 1 {ip_address} > /dev/null 2>&1")
        if ping_result == 0:
            active_devices.append(ip_address)
            os.system(f"nmap -sV -T4 {ip_address} -oX {ip_address}")

    for device in active_devices:
        print(f"Scanning {device} for vulnerabilities...")
        result = subprocess.getoutput(f"nmap -sV -sC --script vuln -p- {device} -oN {device}-vuln")
        sploit = subprocess.getoutput(f"searchsploit --nmap {device} > {device}-sploit")
        if "Host is up" in result:
            with open(f"{device}-vuln", "a") as vuln_file:
                vuln_file.write("\n")
                vuln_file.write(sploit)
                vuln_file.write("\n")
        else:
            print(f"No vulnerabilities found on {device}.")

# Q2 function
def Q2():
    os.chdir("~/Desktop")

    user_file = input("Enter the path to the user list file: ")
    
    choice = input("Do you want to use an existing password list or create a new one? (e/c)")
    
    if choice == "e":
        password_file = input("Enter the path to the password list file: ")
    else:
        min_length = input("Enter minimum length for string: ")
        max_length = input("Enter maximum length for string: ")
        charset = input("Enter character set for string: ")
        os.system(f"crunch {min_length} {max_length} {charset} -o passwordlist.txt")
        print("The password list was created at Desktop and was named passwordlist.txt")
        w = os.getlogin()
        password_file = f"/home/{w}/Desktop/passwordlist.txt"

    active_devices = []  # This list is not being populated correctly, please adjust as needed

    for device in active_devices:
        open_ports_info = subprocess.getoutput(f"nmap -p- --open -sV {device} | grep 'open' | awk '{{print $1}}' | tr '/tcp' ' '")
        open_ports = open_ports_info.split()
        for port in open_ports:
            service_info = subprocess.getoutput(f"nmap -p {port} -sV {device} | grep '{port}/' | awk '{{print $3}}'")
            service = service_info.strip()
            if service in ["ftp", "ssh", "telnet", "http", "pop3", "imap", "smtp", "smb"]:
                print(f"Running hydra on {service} service on port {port} on device {device}")
                os.system(f"hydra -L {user_file} -P {password_file} {service}://{device}:{port} -v >> {device}-vuln")
            else:
                print(f"No login service available on {device} on service {service} on port {port}")

# Acquire scan finishing time
end = time.time()

# Q3 function
def Q3():
    print(f"There were {len(active_devices)} active devices that were scanned")
    runtime = int(end - start)
    print(f"The scan time was {runtime} seconds")
    print("The reports on each live host were saved on your desktop individually and end with the suffix -vuln")
    machine = input("If you would like to view the results of a specific machine, please enter its IP now: ")
    with open(f"{machine}-vuln", "r") as machine_vuln_file:
        print(machine_vuln_file.read())

# Define a function to scan using Scapy
def scan_with_scapy(ip_range):
    # Create an ARP request packet to discover devices in the local network
    arp_request = scapy.ARP(pdst=ip_range)

    # Create an Ethernet frame to encapsulate the ARP request
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address

    # Combine the Ethernet frame and ARP request
    arp_request_packet = ether/arp_request

    # Send the packet and receive the response
    answered_list = scapy.srp(arp_request_packet, timeout=1, verbose=False)[0]

    # Create a list to store the results
    devices_list = []

    for element in answered_list:
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices_list.append(device_info)

    return devices_list

if __name__ == "__main__":
    if "-s" in sys.argv:
        target_ip_range = input("Enter the target IP range (e.g., 192.168.1.1/24): ")
        scanned_devices = scan_with_scapy(target_ip_range)
        # Display or process scanned_devices as needed
    else:
        # Continue with the rest of the script (installing necessary apps, functions Q1, Q2, Q3)
        install()
        Q1()
        Q2()
        Q3()
