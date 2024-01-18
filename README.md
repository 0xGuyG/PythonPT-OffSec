# Python Penetration Testing Excercise Script #

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
