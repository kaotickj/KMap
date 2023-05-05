#!/usr/bin/env python3
# Script: KMap v 0.6
# Author: kaotickj
# Website: kdgwebsolutions.com

import re
import os
import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter import BooleanVar


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

    if not validate_ip_address(ip_address):
        messagebox.showerror("Error", f"Input, \"{ip_address}\" is not a valid IP address or hostname")
        return

    command = f"sudo nmap {verbosity} {scan_type} {timing_option} {nmap_script_option} {aggressive_scan_options} {ip_address} -oA kmapscan_results"
    print(f"{command}")

    os.system(command)
    messagebox.showinfo("Scan Complete", "Scan has completed. Output saved to kmapscan_results.{gnmap}{nmap}{xml}")


root = tk.Tk()
root.title("KMap v 0.6")
logo_file = "alien.png"
if os.path.exists(logo_file):
    logo = PhotoImage(file=logo_file)
    root.wm_iconphoto(True, logo)

# Set up the options frame
options_frame = ttk.LabelFrame(root, text="Scan Options")
options_frame.grid(column=0, row=1, columnspan=2, padx=5, pady=5)

# Set up the IP address entry field
ip_address_label = ttk.Label(options_frame, text="IP address or hostname to scan:")
ip_address_label.grid(column=0, row=0, padx=5, pady=5)

ip_address_entry = ttk.Entry(options_frame)
ip_address_entry.grid(column=1, row=0, padx=5, pady=5)

# Set up the verbosity options
verbosity_label = ttk.Label(options_frame, text="Choose a verbosity option:")
verbosity_label.grid(column=0, row=1, padx=5, pady=5)
verbosity_choice = tk.StringVar(value="-v")
verbosity_options = [
    {"text": "Normal Output", "value": ""},
    {"text": "Verbose Output", "value": "-v"},
    {"text": "Very Verbose Output", "value": "-vv"}
]

verbosity_combobox = ttk.Combobox(options_frame, textvariable=verbosity_choice,
                                  values=[option["value"] for option in verbosity_options], state="readonly")
verbosity_combobox.grid(column=1, row=1, padx=5, pady=5)

# Set up the scan type radio buttons
scan_type_label = ttk.Label(options_frame, text="Choose a scan type:")
scan_type_label.grid(column=0, row=2, padx=5, pady=5)

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
scan_type_frame = ttk.Frame(options_frame)
scan_type_frame.grid(column=1, row=2, padx=5, pady=5)

# Add a label and radiobutton for each scan type option
for i, option in enumerate(scan_type_options):
    ttk.Radiobutton(scan_type_frame, text=option["text"], variable=scan_type_choice, value=option["value"]).grid(
        column=0, row=i, sticky="W", padx=5, pady=2)

# Set up the Nmap script options Combobox
nmap_script_options_label = ttk.Label(options_frame, text="Choose Nmap script options:")
nmap_script_options_label.grid(column=0, row=3, padx=5, pady=5)

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
nmap_script_options_frame = ttk.Frame(options_frame)
nmap_script_options_frame.grid(column=1, row=3, padx=5, pady=5)

# Add a label and radiobutton for each script option
for i, option in enumerate(nmap_script_options):
    ttk.Radiobutton(nmap_script_options_frame, text=option["text"], variable=nmap_script_options_choice,
                    value=option["value"]).grid(column=0, row=i, sticky="W", padx=5, pady=2)

# Set up the timing options radio buttons
timing_option_label = ttk.Label(options_frame, text="Choose a timing option:")
timing_option_label.grid(column=0, row=4, padx=5, pady=5)

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
timing_option_frame = ttk.Frame(options_frame)
timing_option_frame.grid(column=1, row=4, padx=5, pady=5)

# Add a label and radiobutton for each timing option
for i, option in enumerate(timing_option_options):
    ttk.Radiobutton(timing_option_frame, text=option["text"], variable=timing_option_choice,
                    value=option["value"]).grid(column=0, row=i, sticky="W", padx=5, pady=2)

# Set up the Aggressive scan options Checkbutton
# aggressive_scan_options_label = ttk.Label(root, text="Aggressive scan option:")
# aggressive_scan_options_label.grid(column=0, row=2, padx=5, pady=5)

is_aggressive_scan = tk.BooleanVar()
aggressive_scan_options_checkbutton = ttk.Checkbutton(root,
                                                      text="Enable aggressive service and OS detection options (-A -O)",
                                                      variable=is_aggressive_scan)
aggressive_scan_options_checkbutton.grid(column=0, row=2, padx=5, pady=5)

# Add a button to start the scan
start_button = ttk.Button(root, text="Start Scan", command=start_scan)
start_button.grid(column=0, row=3, columnspan=2, padx=5, pady=5)
root.mainloop()
