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


print(f" \n")
print(f" {RED} ██ ▄█▀ ███▄ ▄███▓ ▄▄▄       ██▓███  ")
print(f" {RED} ██▄█▒ ▓██▒▀█▀ ██▒▒████▄    ▓██░  ██▒")
print(f" {RED}▓███▄░ ▓██    ▓██░▒██  ▀█▄  ▓██░ ██▓▒")
print(f" {RED}▓██ █▄ ▒██    ▒██ ░██▄▄▄▄██ ▒██▄█▓▒ ▒")
print(f" {RED}▒██▒ █▄▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ░  ░")
print(f" {RED}▒ ▒▒ ▓▒░ ▒░   ░  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░")
print(f" {RED}░ ░▒ ▒░░  ░      ░  ▒   ▒▒ ░░▒ ░     ")
print(f" {RED}░ ░░ ░ ░      ░     ░   ▒   ░░       ")
print(f" {RED}░  ░          ░         ░  ░         ")
print(f"	{FGC}{LIGHT_CYAN} 🕵🔎 Courtesy of KaotickJ 👽 {NC}\n")

print(f" \n KMap v 0.1 {NC}{LIGHT_MAGENTA}\n\n KMap is a user friendly tool for running various types of nmap scans allowing user to set scan parameters by making simple choices.\n")
print(f" \n {NC}{LIGHT_CYAN}\n\n Before running the scan, you will need to set some options to construct the nmap command-line arguments:\n")

while True:
    ip_address = input(f" {FGC}{GREEN} Enter the IP address or hostname to scan:{NC} {DG}")

    # Validate input as IP address or hostname
    if re.match('^([0-9]{1,3}\.){3}[0-9]{1,3}$', ip_address) or re.match('^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.[a-zA-Z]{2,}$', ip_address):
        break
    else:
        print(f"{RED} Input, \"{ip_address}\" is not a valid IP address or hostname{NC}")
        continue

while True:
    # Prompt user to choose verbosity level
    print(f"\n{BLUE} Please choose a verbosity option from the list below:\n{YELLOW} 1. Normal Output\n 2. Verbose Output (-v)\n 3. Very Verbose Output (-vv)\n")
    verbosity_choice = input(f" {FGC}{GREEN} Enter a number:{NC} {DG}")

    if verbosity_choice == '1':
        verbosity = ''
        break
    elif verbosity_choice == '2':
        verbosity = "-v"
        break
    elif verbosity_choice == '3':
        verbosity = "-vv"
        break
    else:
        print(f"{RED} Invalid verbosity option: \"{verbosity_choice}\"")
        continue

while True:
    # Prompt user to choose scan type
    print(f"\n{BLUE} Please choose a scan type from the list below:\n{YELLOW} 1. TCP SYN Scan (-sS)\n 2. TCP Connect Scan (-sT)\n 3. UDP Scan (-sU)\n 4. TCP + UDP + Service Detection (-sS -sU -sV)\n")
    scan_type_choice = input(f" {FGC}{GREEN} Enter a number:{NC} {DG}")

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
        print(f"{RED} Invalid scan type choice: \"{scan_type_choice}\"")
        continue

while True:
    # Prompt user to choose timing option
    print(f"\n{BLUE} Please choose a timing option from the list below:\n{YELLOW} 1. T0 (Paranoid)\n 2. T1 (Sneaky)\n 3. T2 (Polite)\n 4. T3 (Normal)\n 5. T4 (Aggressive)\n 6. T5 (Insane)\n")
    timing_choice = input(f" {FGC}{GREEN}Enter a number:{NC} {DG}")

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
        print(f"{RED} Invalid timing option choice")
        continue

while True:
    # Prompt user to choose script option
    print(f"\n{BLUE} Please choose a script option from the list below:\n (Note that some of these options are very slow, and may require root permission)\n{YELLOW} 1. default (-sC)\n 2. vuln\n 3. auth\n 4. intrusive\n 5. safe\n 6. all\n 7. none\n")
    script_choice = input(f" {FGC}{GREEN} Enter a number:{NC} {DG}")

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
        print(f"\n{RED} Invalid choice. Please choose a valid script option.{DG}")

while True:
    # Prompt user to choose port scan option
    print(f"\n{BLUE} Please choose a ports to scan option from the list below:\n{YELLOW} 1. Top 20\n 2. Top 100\n 3. Top 1000\n 4. All Ports\n 5. Custom Port Range\n")
    ports_choice = input(f" {FGC}{GREEN} Enter a number:{NC} {DG}")

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
        ports_range = input(f" {FGC}{GREEN} Enter a port range (i.e, 1-1024):{NC} {DG}")
        ports_option = f"-p {ports_range}"
        break
    else:
        print(f"\n{RED}Invalid choice. Please choose a valid ports option.{DG}")
        
while True:
    # Prompt user to choose aggessive scan options
    print(f"\n{BLUE} Please choose aggressive scan options from the list below:\n (Note that these scan types are very slow, and may require root permission)\n{YELLOW} 1. Aggressive service detection (-A)\n 2. OS Detection (-O)\n 3. Aggressive Service Detection and OS Detection (-A -O)\n 4. None\n")
    aggressive_choice = input(f" {FGC}{GREEN} Enter a number:{NC} {DG}")

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
        print(f"\n{RED} Invalid choice. Please choose a valid aggressive scan option.{DG}")

# Construct Nmap command
nmap_command = f"sudo nmap {verbosity} {aggressive_option} {scan_type} {timing_option} {script_option} {ip_address} {ports_option} -oA {ip_address}"

# Run Nmap command and print output
print(f"\n{GREEN} Running Nmap scan command: {DG}{nmap_command}")
scan_output = os.popen(nmap_command).read()
print(f"\n{GREEN} Nmap scan output:\n{DG}{scan_output}")
print(f"\n{GREEN} Nmap scan complete. \n{LIGHT_CYAN} Scan results saved to:\n    {YELLOW}{ip_address}.xml\n    {ip_address}.gnmap\n    {ip_address}.nmap")
        
