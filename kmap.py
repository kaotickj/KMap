#!/usr/bin/env python3
# Script: KMap v 0.1
# Author: kaotickj
# Website: kdgwebsolutions.com

import re
import os

BLUE = '\033[1;34m'
DG = '\033[0m'
YELLOW = '\033[1;33m'
RED = '\033[1;31m'
LIGHT_MAGENTA='\033[1;95m'
GREEN='\033[1;32m'
FGC='\033[48;5;237m'
NC='\033[0m'
LIGHT_CYAN='\033[1;96m'

print(f" \n{FGC}{GREEN} KMap v 0.1 {NC}{LIGHT_MAGENTA}\n\n KMap is a user friendly tool for running various types of nmap scans allowing user to set scan parameters by making simple choices.\n")
print(f"{FGC}{LIGHT_CYAN} 🕵🔎 Courtesy of KaotickJ 👽 {NC}\n")
while True:
    ip_address = input(f"{BLUE}Enter the IP address or hostname to scan: {DG}")

    # Validate input as IP address or hostname
    if re.match('^([0-9]{1,3}\.){3}[0-9]{1,3}$', ip_address) or re.match('^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.[a-zA-Z]{2,}$', ip_address):
        break
    else:
        print(f"Input, \"{ip_address}\" is not a valid IP address or hostname")
        continue

while True:
    # Prompt user to choose scan type
    print(f"{BLUE}Please choose a scan type from the list below:\n{YELLOW}1. TCP SYN Scan (-sS)\n2. TCP Connect Scan (-sT)\n3. UDP Scan (-sU)\n4. TCP + UDP + Service Detection (-sS -sU -sV)\n")
    scan_type_choice = input(f"{BLUE}Enter a number: {DG}")

    if scan_type_choice == '1':
        scan_type = "-sS"
        break
    elif scan_type_choice == '2':
        scan_type = "-sT"
        break
    elif scan_type_choice == '3':
        scan_type = "-sU"
        break
    elif scan_type_choice == '4':
        scan_type = "-sS -sU -sV"
        break
    else:
        print(f"{RED}Invalid scan type choice: \"{scan_type_choice}\"")
        continue

while True:
    # Prompt user to choose timing option
    print(f"\n{BLUE}Please choose a timing option from the list below:\n{YELLOW}1. T0 (Paranoid)\n2. T1 (Sneaky)\n3. T2 (Polite)\n4. T3 (Normal)\n5. T4 (Aggressive)\n6. T5 (Insane)\n")
    timing_choice = input(f"{BLUE}Enter a number: {DG}")

    if timing_choice == '1':
        timing_option = "-T0"
        break
    elif timing_choice == '2':
        timing_option = "-T1"
        break
    elif timing_choice == '3':
        timing_option = "-T2"
        break
    elif timing_choice == '4':
        timing_option = "-T3"
        break
    elif timing_choice == '5':
        timing_option = "-T4"
        break
    elif timing_choice == '6':
        timing_option = "-T5"
        break
    else:
        print(f"{RED}Invalid timing option choice")
        continue

while True:
    # Prompt user to choose script option
    print(f"\n{BLUE}Please choose a script option from the list below:\n{YELLOW}1. default (-sC)\n2. vuln\n3. auth\n4. intrusive\n5. safe\n6. all\n7. none\n")
    script_choice = input(f"{BLUE}Enter a number: {DG}")

    if script_choice == '1':
        script_option = "-sC"
        break
    elif script_choice == '2':
        script_option = "--script vuln"
        break
    elif script_choice == '3':
        script_option = "--script auth"
        break
    elif script_choice == '4':
        script_option = "--script intrusive"
        break
    elif script_choice == '5':
        script_option = "--script safe"
        break
    elif script_choice == '6':
        script_option = "--script all"
        break
    elif script_choice == '7':
        script_option = ""
        break
    else:
        print(f"\n{RED}Invalid choice. Please choose a valid script option.{DG}")

while True:
    # Prompt user to choose port scan option
    print(f"\n{BLUE}Please choose a ports to scan option from the list below:\n{YELLOW}1. Top 20\n2. Top 100\n3. Top 1000\n4. All Ports\n5. Custom Port Range\n")
    ports_choice = input(f"{BLUE}Enter a number: {DG}")

    if ports_choice == '1':
        ports_option = "--top-ports 20"
        break
    elif ports_choice == '2':
        ports_option = "--top-ports 100"
        break
    elif ports_choice == '3':
        ports_option = "--top-ports 1000"
        break
    elif ports_choice == '4':
        ports_option = "-p-"
        break
    elif ports_choice == '5':
        ports_range = input(f"{BLUE}Enter a port range (i.e, 1-1024): {DG}")
        ports_option = f"-p {ports_range}"
        break
    else:
        print(f"\n{RED}Invalid choice. Please choose a valid ports option.{DG}")
        
while True:
    # Prompt user to choose aggessive scan options
    print(f"\n{BLUE}Please choose aggressive scan options from the list below:\n(Note that these scan types are very slow, and may require root permission)\n{YELLOW}1. Aggressive service detection (-A)\n2. OS Detection (-O)\n3. Aggressive Service Detection and OS Detection (-A -O)\n4. None\n")
    aggressive_choice = input(f"{BLUE}Enter a number: {DG}")

    if aggressive_choice == '1':
        aggressive_option = "-A"
        break
    elif aggressive_choice == '2':
        aggressive_option = "-O"
        break
    elif aggressive_choice == '3':
        aggressive_option = "-A -O"
        break
    elif aggressive_choice == '4':
        aggressive_option = ""
        break
    else:
        print(f"\n{RED}Invalid choice. Please choose a valid aggressive scan option.{DG}")

# Construct Nmap command
nmap_command = f"sudo nmap -vv {aggressive_option} {scan_type} {timing_option} {script_option} {ip_address} {ports_option} -oA {ip_address}"

# Run Nmap command and print output
print(f"{BLUE}Running Nmap scan command: {DG}{nmap_command}")
scan_output = os.popen(nmap_command).read()
print(f"\n{BLUE}Nmap scan output:\n{DG}{scan_output}")
        
