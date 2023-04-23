#!/bin/bash

read -p "Enter the IP address to scan: " ip_address

echo "
Please choose a scan type from the list below:
1. TCP SYN Scan (-sS)
2. TCP Connect Scan (-sT)
3. UDP Scan (-sU)
4. TCP + UDP + Service Detection (-sS -sU -sV)
"
read -p "Enter a number: " scan_type_choice

case $scan_type_choice in
    1) scan_type="sS";;
    2) scan_type="sT";;
    3) scan_type="sU";;
    4) scan_type="sS -sU -sV";;
    *) echo "Invalid scan type choice"; exit 1;;
esac

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
    1) script_option="default";;
    2) script_option="vuln";;
    3) script_option="auth";;
    4) script_option="intrusive";;
    5) script_option="safe";;
    6) script_option="all";;
    7) script_option="";;
    *) echo "Invalid script option choice"; exit 1;;
esac

echo "
Please choose a port scan option from the list below (press Enter without choosing an option to input a range of ports) :
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
       port_option="-p $port_range";;
    *) echo "Invalid port option choice"; exit 1;;   
esac

echo
read -p "Use Aggressive scan + OS Detection ( y or n)? " aggressive_option_choice

case $aggressive_option_choice in
    y) aggressive_option="-A -O";;
    n) aggressive_option="";;
    *) echo "Invalid aggressive scan option choice"; exit 1;;   
esac

echo
read -p "Save output from scan ( y or n)? " save_option_choice

case $save_option_choice in
    y) read -p "Enter filename to save: " save_filename; save_option="-oA $save_filename";;
    n) save_option="";;
    *) echo "Invalid save option choice"; exit 1;;   
esac

echo -e "\nScanning $ip_address..."
nmap_args=(" -vv -$scan_type $timing_option $aggressive_option --script=$script_option $port_option $ip_address $save_option")
sudo nmap $nmap_args
echo -e "\n\nScan complete"
if [[ -n $save_option ]]; then
    echo -e "\nScan results saved to $save_filename.nmap, $save_filename.gnmap, and $save_filename.xml"
fi
