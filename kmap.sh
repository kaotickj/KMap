#!/bin/bash

# Prompt user for IP address or host to scan
read -p "Enter the IP address or hostname to scan: " ip_address

# Prompt user to choose scan type
echo "
Please choose a scan type from the list below:
1. TCP SYN Scan (-sS)
2. TCP Connect Scan (-sT)
3. UDP Scan (-sU)
4. TCP + UDP + Service Detection (-sS -sU -sV)
"
read -p "Enter a number: " scan_type_choice

case $scan_type_choice in
    1) scan_type="-sS";;
    2) scan_type="-sT";;
    3) scan_type="-sU";;
    4) scan_type="-sS -sU -sV";;
    *) echo "Invalid scan type choice"; exit 1;;
esac

# Prompt user to choose timing option
echo "
Please choose a timing option from the list below:
1. T0 (Paranoid)
2. T1 (Sneaky)
3. T2 (Polite)
4. T3 (Normal)
5. T4 (Aggressive)
6. T5 (Insane)
"
read -p "Enter a number: " timing_choice

case $timing_choice in
    1) timing_option="-T0";;
    2) timing_option="-T1";;
    3) timing_option="-T2";;
    4) timing_option="-T3";;
    5) timing_option="-T4";;
    6) timing_option="-T5";;
    *) echo "Invalid timing option choice"; exit 1;;
esac

# Prompt user to choose script option
echo "
Please choose a script option from the list below:
1. default (-sC)
2. vuln
3. auth
4. intrusive
5. safe
6. all
7. none
"
read -p "Enter a number: " script_choice

case $script_choice in
    1) script_option="-sC";;
    2) script_option="--script vuln";;
    3) script_option="--script auth";;
    4) script_option="--script intrusive";;
    5) script_option="--script safe";;
    6) script_option="--script all";;
    7) script_option="";;
    *) echo "Invalid script option choice"; exit 1;;
esac

# Prompt user to choose port scan option
echo "
Please choose a port scan option from the list below (press Enter without choosing an option to input a range of ports):
1. Top 20 ports
2. Top 100 ports
3. Top 1000 ports
4. All ports
5. Enter a range of ports
"
read -p "Enter a number: " port_option_choice

case $port_option_choice in
    1) port_option="--top-ports 20";;
    2) port_option="--top-ports 100";;
    3) port_option="--top-ports 1000";;
    4) port_option="-p-";;
    5) read -p "Enter port range to scan (e.g. 1-1024): " port_range
	if ! [[ "$port_range" =~ ^[0-9]+-[0-9]+$ ]]; then
   	    echo "Invalid port range format. Please enter a range in the format of 'start-end' (e.g. 1-1024)"
	    exit 1
	fi
        port_option="-p $port_range";;
    *) echo "Invalid port option choice"; exit 1;;
esac

# Sets the appropriate nmap option based on the user's choice for aggressive scan and OS detection.
echo
read -p "Use Aggressive scan + OS Detection ( y or n)? " aggressive_option_choice

case $aggressive_option_choice in
    y) aggressive_option="-A -O";;
    n) aggressive_option="";;
    *) echo "Invalid aggressive scan option choice"; exit 1;;
esac

# Sets the appropriate nmap option based on the user's choice for saving the output from the scan.
echo
read -p "Save output from scan ( y or n)? " save_option_choice

case $save_option_choice in
    y) read -p "Enter filename to save: " save_filename; save_option="-oA $save_filename";;
    n) save_option="";;
    *) echo "Invalid save option choice"; exit 1;;
esac

# Runs the nmap scan with the chosen options.
echo -e "\nScanning $ip_address..."
nmap_args=(" -vv $scan_type $timing_option $aggressive_option $script_option $port_option $ip_address $save_option")
sudo nmap $nmap_args
echo -e "\n\nScan complete"

# If the user chose to save the output from the scan, displays the filenames where the output was saved.
if [[ -n $save_option ]]; then
    echo -e "\nScan results saved to $save_filename.nmap, $save_filename.gnmap, and $save_filename.xml"
fi
