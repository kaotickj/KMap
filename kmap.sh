#!/bin/bash
# Script: KMap v 0.1
# Author: kaotickj
# Website: kdgwebsolutions.com

###########################################
#---------------  Colors  ----------------#
###########################################

C=$(printf '\033')
FGR="${C}[48;5;196m"
RED="${C}[1;31m"
SED_RED="${C}[1;31m&${C}[0m"
GREEN="${C}[1;32m"
FGG="${C}[48;5;22m"
SED_GREEN="${C}[1;32m&${C}[0m"
YELLOW="${C}[1;33m"
SED_YELLOW="${C}[1;33m&${C}[0m"
SED_RED_YELLOW="${C}[1;31;103m&${C}[0m"
BLUE="${C}[1;34m"
FGB="${C}[48;5;34m"
SED_BLUE="${C}[1;34m&${C}[0m"
ITALIC_BLUE="${C}[1;34m${C}[3m"
LIGHT_MAGENTA="${C}[1;95m"
SED_LIGHT_MAGENTA="${C}[1;95m&${C}[0m"
LIGHT_CYAN="${C}[1;96m"
FGC="${C}[48;5;237m"
SED_LIGHT_CYAN="${C}[1;96m&${C}[0m"
LG="${C}[1;37m"
SED_LG="${C}[1;37m&${C}[0m"
DG="${C}[1;90m"
SED_DG="${C}[1;90m&${C}[0m"
NC="${C}[0m"
UNDERLINED="${C}[5m"
ITALIC="${C}[3m"
function goto
{
    label=$1
#    shift;
    cmd=$(sed -n "/$label:/{:a;n;p;ba};" $0 | grep -v ':$')
    eval "$cmd"
    exit
}

function pause(){
   read -p "$*"
}

function pingFirst
{
    echo
    # Prompt user to choose to ping or not before continuing.  
    read -p "${BLUE}Ping first? It may be useful to check if the host is up. (y or n) ${DG}" ping_choice 

    case $ping_choice in
        y)
	echo "${FGC}${YELLOW}pinging $ip_address hit ctrl + c to stop pinging and continue${NC}${LIGHT_CYAN}";
	ping $ip_address;;
	n);;
	*);;
    esac
}

################################################################################
################################################################################
# Main program                                                                 #
################################################################################
################################################################################
echo "    ${RED}"
echo -e "
	 ██ ▄█▀ ███▄ ▄███▓ ▄▄▄       ██▓███  
	 ██▄█▒ ▓██▒▀█▀ ██▒▒████▄    ▓██░  ██▒
	▓███▄░ ▓██    ▓██░▒██  ▀█▄  ▓██░ ██▓▒
	▓██ █▄ ▒██    ▒██ ░██▄▄▄▄██ ▒██▄█▓▒ ▒
	▒██▒ █▄▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ░  ░
	▒ ▒▒ ▓▒░ ▒░   ░  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░
	░ ░▒ ▒░░  ░      ░  ▒   ▒▒ ░░▒ ░     
	░ ░░ ░ ░      ░     ░   ▒   ░░       
	░  ░          ░         ░  ░         
"
echo -ne '   👽\r'
sleep .1
echo -ne '   👽👽\r'
sleep .1
echo -ne '   👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽\r'
sleep .1
echo -ne '   👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽👽\r'
echo -ne '                   '"${FGC}${LIGHT_CYAN}"' 🕵🔎 Courtesy of KaotickJ 👽 \r'${NC}
sleep .5
echo "${LIGHT_MAGENTA}  "
echo
echo "  KMap is a user friendly tool for running various types of nmap scans with simple choice parameters" |fmt -w 60
echo 
pause  '  '${FGC}${GREEN}' Press [Enter] key to continue...'${NC}

clear
echo
echo    
#ip_enter:
# Prompt user for IP address or host to scan
read -p "${BLUE}Enter the IP address or hostname to scan: ${DG}" ip_address

# Validate input as IP address or hostname
if [[ $ip_address =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || \
      $ip_address =~ ^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.[a-zA-Z]{2,}$ ]]; then
    goto scanType
else
    echo "Input, \"$ip_address\" is not a valid IP address or hostname"
    goto ip_enter
fi
# Uncomment the line below to add an option to ping the ip address before continuing.  This can be useful to check if the host is up before scanning.
# pingFirst

#scanType:
# Prompt user to choose scan type
echo "${BLUE}
Please choose a scan type from the list below:
${YELLOW}1. TCP SYN Scan (-sS)
2. TCP Connect Scan (-sT)
3. UDP Scan (-sU)
4. TCP + UDP + Service Detection (-sS -sU -sV)
"
read -p "${BLUE}Enter a number: ${DG}" scan_type_choice

case $scan_type_choice in
    1) scan_type="-sS";;
    2) scan_type="-sT";;
    3) scan_type="-sU";;
    4) scan_type="-sS -sU -sV";;
    *) echo "${RED}Invalid scan type choice"; goto scanType;;
esac

#timing:
# Prompt user to choose timing option
echo "
${BLUE}Please choose a timing option from the list below:
${YELLOW}1. T0 (Paranoid)
2. T1 (Sneaky)
3. T2 (Polite)
4. T3 (Normal)
5. T4 (Aggressive)
6. T5 (Insane)
"
read -p "${BLUE}Enter a number: ${DG}" timing_choice

case $timing_choice in
    1) timing_option="-T0";;
    2) timing_option="-T1";;
    3) timing_option="-T2";;
    4) timing_option="-T3";;
    5) timing_option="-T4";;
    6) timing_option="-T5";;
    *) echo "${RED}Invalid timing option choice"; goto timing;;
esac

#scripts:
# Prompt user to choose script option
echo "
${BLUE}Please choose a script option from the list below:
${YELLOW}1. default (-sC)
2. vuln
3. auth
4. intrusive
5. safe
6. all
7. none
"
read -p "${BLUE}Enter a number: ${DG}" script_choice

case $script_choice in
    1) script_option="-sC";;
    2) script_option="--script vuln";;
    3) script_option="--script auth";;
    4) script_option="--script intrusive";;
    5) script_option="--script safe";;
    6) script_option="--script all";;
    7) script_option="";;
    *) echo "${RED}Invalid script option choice"; goto scripts;;
esac

#port:
# Prompt user to choose port scan option
echo "
${BLUE}Please choose a port scan option from the list below (press Enter without choosing an option to input a range of ports):
${YELLOW}1. Top 20 ports
2. Top 100 ports
3. Top 1000 ports
4. All ports
5. Enter a range of ports
"
read -p "${BLUE}Enter a number: ${DG}" port_option_choice

case $port_option_choice in
    1) port_option="--top-ports 20";;
    2) port_option="--top-ports 100";;
    3) port_option="--top-ports 1000";;
    4) port_option="-p-";;
    5) read -p "${BLUE}Enter port range to scan (e.g. 1-1024): ${DG}" port_range
	if ! [[ "$port_range" =~ ^[0-9]+-[0-9]+$ ]]; then
   	    echo "${RED}Invalid port range format. Please enter a range in the format of 'start-end' (e.g. 1-1024)"
	    exit 1
	fi
        port_option="-p $port_range";;
    *) echo "${RED}Invalid port option choice"; goto port;;
esac

#aggressive:
# Sets the appropriate nmap option based on the user's choice for aggressive scan and OS detection.
echo
read -p "${BLUE}Use Aggressive scan + OS Detection ( y or n)? ${DG}" aggressive_option_choice

case $aggressive_option_choice in
    y) aggressive_option="-A -O";;
    n) aggressive_option="";;
    *) echo "${RED}Invalid aggressive scan option choice"; goto aggressive;;
esac

#save:
# Sets the appropriate nmap option based on the user's choice for saving the output from the scan.
echo
read -p "${BLUE}Save output from scan ( y or n)? ${DG}" save_option_choice

case $save_option_choice in
    y)
        read -p "${BLUE}Enter filename to save: ${DG}" save_filename;
        save_option="-oA $save_filename";;
    n) save_option="";;
    *) echo "${RED}Invalid save option choice"; goto save;;
esac

# Runs the nmap scan with the chosen options.
echo -e "${LG}\nScanning $ip_address..."
nmap_args=(" -vv $scan_type $timing_option $aggressive_option $script_option $port_option $ip_address $save_option")
sudo nmap $nmap_args
echo -e "${GREEN}\n\nScan complete"

# If the user chose to save the output from the scan, displays the filenames where the output was saved.
if [[ -n $save_option ]]; then
    echo -e "\nScan results saved to $save_filename.nmap, $save_filename.gnmap, and $save_filename.xml"| fmt -w 60
fi
