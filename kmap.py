#!/usr/bin/env python3
# Script: KMap v 0.8
# Author: kaotickj
# Website: kdgwebsolutions.com

import re
import os
import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import messagebox


def validate_ip_address(ip_address):
    # Validate input as IP address or hostname
    if re.match('^([0-9]{1,3}\.){3}[0-9]{1,3}$', ip_address) or re.match(
            '^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.[a-zA-Z]{2,}$', ip_address):
        return True
    else:
        return False


def start_scan():
    ip_address = ip_address_entry.get()
    verbosity = verbosity_choice.get()
    scan_type = scan_type_choice.get()
    timing_option = timing_option_choice.get()
    nmap_script_option = nmap_script_options_choice.get()
    aggressive_scan_options = "-A -O" if is_aggressive_scan.get() else ""
    port_option = port_option_choice.get()
    if not port_option_choice.get():
        port_option = ""
    port_option_range = port_option_range_choice + port_option_range_entry.get()
    if not port_option_range_entry.get():
        port_option_range = ""
    addt_args = addt_args_entry.get() 
    if not validate_ip_address(ip_address):
        messagebox.showerror("Error", f"Input, \"{ip_address}\" is not a valid IP address or hostname")
        return

    command = f"sudo nmap {verbosity} {scan_type} {addt_args} {timing_option} {port_option} {port_option_range} {nmap_script_option} {aggressive_scan_options} {ip_address} -oA kmapscan_results"
    print(f"{command}")

    os.system(command)
    messagebox.showinfo("Scan Complete", "Scan has completed. Output saved to kmapscan_results.{gnmap}{nmap}{xml}")


root = tk.Tk()
root.title("KMap v 0.8")
logo_file = "alien.png"
if os.path.exists(logo_file):
    logo = PhotoImage(file=logo_file)
    root.wm_iconphoto(True, logo)

# Set up the IP address entry field
ip_address_label = ttk.Label(root, text="IP address or hostname to scan:")
ip_address_label.grid(column=0, row=0, padx=5, pady=5)
ip_address_entry = ttk.Entry(root)
ip_address_entry.insert(0, "scanme.org")
ip_address_entry.grid(column=1, row=0, padx=5, pady=5)

# Set up the options frame
options_frame = ttk.LabelFrame(root, text="Scan Options")
options_frame.grid(column=0, row=1, columnspan=2, padx=5, pady=5)

# Set up the verbosity options
verbosity_choice = tk.StringVar(value="-v")
verbosity_options = [
    {"text": "Normal Output", "value": ""},
    {"text": "Verbose Output", "value": "-v"},
    {"text": "Very Verbose Output", "value": "-vv"}
]
# Create a frame to group the verbosity options
verbosity_options_frame = ttk.LabelFrame(options_frame, text="Verbosity Options")
verbosity_options_frame.grid(column=0, row=0, padx=5, pady=5)
# Add a label and radiobutton for each verbosity option
for i, option in enumerate(verbosity_options):
    ttk.Radiobutton(verbosity_options_frame, text=option["text"], variable=verbosity_choice, value=option["value"]).grid(
        column=0, row=i, sticky="W", padx=5, pady=2)

# Set up the scan type radio buttons
scan_type_choice = tk.StringVar(value="-sS")
scan_type_options = [
    {"text": "TCP SYN scan (-sS)", "value": "-sS"},
    {"text": "TCP connect scan (-sT)", "value": "-sT"},
    {"text": "UDP scan (-sU)", "value": "-sU"},
    {"text": "TCP NULL scan (-sN)", "value": "-sN"},
    {"text": "TCP FIN scan (-sF)", "value": "-sF"},
    {"text": "TCP Xmas scan (-sX)", "value": "-sX"}
]
# Create a frame to group the scan type options
scan_type_frame = ttk.LabelFrame(options_frame, text="Scan Types")
scan_type_frame.grid(column=0, row=1, padx=5, pady=5)
# Add a label and radiobutton for each scan type option
for i, option in enumerate(scan_type_options):
    ttk.Radiobutton(scan_type_frame, text=option["text"], variable=scan_type_choice, value=option["value"]).grid(
        column=1, row=i, sticky="W", padx=5, pady=2)

# Set up the Nmap script options
nmap_script_options_choice = tk.StringVar(value="")  # default value is empty
nmap_script_options = [
    {"text": "No scripts", "value": ""},
    {"text": "Authentication scripts (auth)", "value": "--script auth"},
    {"text": "Default scripts (default)", "value": "--script default"},
    {"text": "Exploit detection (exploit)", "value": "--script exploit"},
    {"text": "Vulnerability detection (vuln)", "value": "--script vuln"},
    {"text": "All scripts (all)", "value": "--script all"}
]
# Create a frame to group the script options
nmap_script_options_frame = ttk.LabelFrame(options_frame, text="Script Options")
nmap_script_options_frame.grid(column=1, row=0, padx=5, pady=5)
# Add a label and radiobutton for each script option
for i, option in enumerate(nmap_script_options):
    ttk.Radiobutton(nmap_script_options_frame, text=option["text"], variable=nmap_script_options_choice,
                    value=option["value"]).grid(column=1, row=i, sticky="W", padx=5, pady=2)

# Set up the timing options radio buttons
timing_option_choice = tk.StringVar(value="-T3")
timing_option_options = [
    {"text": "Paranoid timing (-T0)", "value": "-T0"},
    {"text": "Sneaky timing (-T1)", "value": "-T1"},
    {"text": "Polite timing (-T2)", "value": "-T2"},
    {"text": "Default (normal) timing (-T3)", "value": "-T3"},
    {"text": "Aggressive timing (-T4)", "value": "-T4"},
    {"text": "Insane timing (-T5)", "value": "-T5"}
]
# Create a frame to group the timing options
timing_option_frame = ttk.LabelFrame(options_frame, text="Timing Options")
timing_option_frame.grid(column=1, row=1, padx=5, pady=5)
# Add a label and radiobutton for each timing option
for i, option in enumerate(timing_option_options):
    ttk.Radiobutton(timing_option_frame, text=option["text"], variable=timing_option_choice,
                    value=option["value"]).grid(column=4, row=i, sticky="W", padx=5, pady=2)

# Set up the port options radio buttons
port_options_label = ttk.Label(root, text="Port Options")
port_options_label.grid(column=0, row=0, padx=5, pady=5)

port_option_choice = tk.StringVar(value="")
port_option_options = [
    {"text": "Default", "value": ""},
    {"text": "Top 20", "value": "--top-ports 20"},
    {"text": "Top 100", "value": "--top-ports 100"},
    {"text": "Top 1000", "value": "--top-ports 1000"},
    {"text": "All Ports (* Very Slow)", "value": "-p-"},
]
# Create a frame to group the port options
port_option_frame = ttk.LabelFrame(options_frame, text="Port Options")
port_option_frame.grid(column=0, row=3, padx=5, pady=5)
# Add a label and radiobutton for each port option
for i, option in enumerate(port_option_options):
    ttk.Radiobutton(port_option_frame, text=option["text"], variable=port_option_choice,
                    value=option["value"]).grid(column=0, row=i, sticky="W", padx=5, pady=2)

# Create a frame to group the Additional arguments element
param_option_frame = ttk.LabelFrame(options_frame, text="Additional Parameters")
param_option_frame.grid(column=1, row=3, padx=5, pady=5)

port_option_range = ttk.Label(param_option_frame, text="Specific Port or Range - Only if\nyou didn't set a Port Option")
port_option_range.grid(column=0, row=0, sticky="W", padx=5, pady=2)
port_option_range_entry = ttk.Entry(param_option_frame)
port_option_range_entry.grid(column=0, row=1, sticky="W", padx=5, pady=5)
port_option_range_choice = "-p "

addt_args = ttk.Label(param_option_frame, text="Additional Arguments")
addt_args.grid(column=0, row=2, sticky="W", padx=5, pady=2)
addt_args_entry = ttk.Entry(param_option_frame)
addt_args_entry.grid(column=0, row=3, sticky="W", padx=5, pady=5)

# Set up the Aggressive scan options Checkbutton
is_aggressive_scan = tk.BooleanVar()
aggressive_scan_options_checkbutton = ttk.Checkbutton(root,
                                                      text="Enable aggressive service and OS detection options (-A -O)",
                                                      variable=is_aggressive_scan)
aggressive_scan_options_checkbutton.grid(column=0, row=3, columnspan=2, padx=5, pady=5)

# Add a button to start the scan
start_button = ttk.Button(root, text="Start Scan", command=start_scan)
start_button.grid(column=0, row=4, columnspan=2, padx=5, pady=5)

root.mainloop()
