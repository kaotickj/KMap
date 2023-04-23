# KMap
This is a Bash script that prompts the user to enter an IP address to scan, and then presents a series of options for customizing the Nmap scan. The options include selecting the type of scan, the timing option, the script option, the port scan option, and whether to use aggressive scanning and OS detection, as well as whether to save the output from the scan. 
### Dependencies:
* nmap
```
sudo apt install nmap
```
 to use:
 ```
 chmod +x kmap.sh
 ./kmap.sh
 ```
After the user has selected all of the options, the script constructs the appropriate command-line arguments for the nmap command and runs the scan with sudo nmap. Finally, the script displays a message indicating that the scan is complete and, if the user chose to save the output, the filenames of the saved results.