# KMap
This is a Bash script that prompts for an IP address to scan, and then presents a series of options for customizing the Nmap scan. The options include selecting the type of scan, the timing option, the script option, the port scan option, and whether to use aggressive scanning and OS detection, as well as whether to save the output from the scan. 
### Dependencies:
* nmap
```
sudo apt install nmap
```
### Usage:
* First, add executable permission:
 ```
 chmod +x kmap.sh
 ```
 * For simplicity sake, run as root, as some scan options such as OS Detection require elevated privileges:
 ```
 sudo ./kmap.sh
 ```
After the "splash screen" loads, hit enter, and follow the prompts to enter the parameters for the scan.
After collecting all of the options, the script constructs the appropriate command-line arguments for the nmap command and runs the scan with sudo nmap. Finally, the script displays a message indicating that the scan is complete and, if the user chose to save the output, the filenames of the saved results.