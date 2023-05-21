#!/usr/bin/env python3
# Script: KMap v 1.0.2
# Author: kaotickj
# Website: https://github.com/kaotickj/KMap/

import re
import os
import tkinter as tk
import webbrowser
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog

version = "1.0.2"

if os.geteuid() != 0:
    import sys

    print(
        "Because many nmap scan options require root permissions, this script must be run as root. Please run with "
        "'sudo python3 kmap.py'.")
    sys.exit(1)


def validate_port_input(input_string):
    """
    Validates the input string for port specification in nmap scan.
    Acceptable input formats are:
    - Specific port: '22'
    - Multiple ports: '21,22,23'
    - Port range: '21-25'
    """
    # Check for specific port
    if re.match('^\d{1,5}$', input_string):
        return True

    # Check for multiple ports separated by comma
    elif re.match('^\d{1,5}(,\d{1,5})+$', input_string):
        return True

    # Check for port range
    elif re.match('^\d{1,5}-\d{1,5}$', input_string):
        return True

    # Invalid input format
    else:
        return False


class AboutDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("About KMap")
        self.resizable(False, False)
        self.geometry("400x300+240+240")

        # create widgets
        label_version = tk.Label(self, text=f"KMap Version {version}", font=("TkDefaultFont", 12, "bold"))
        label_version.pack(pady=10)

        label_description = tk.Label(self,
                                     text=f"KMap {version} provides a graphical user interface\n solution for running "
                                          f"nmap scans in Linux.",
                                     justify="center")
        label_description.pack(pady=10)

        label_author = tk.Label(self, text="Author: kaotickj", font=("TkDefaultFont", 10))
        label_author.pack()

        label_github = tk.Label(self, text="GitHub: https://github.com/kaotickj/KMap/", font=("TkDefaultFont", 10),
                                fg="blue", cursor="hand2")
        label_github.pack(pady=10)
        label_github.bind("<Button-1>", self.on_github_clicked)

        label_license_header = tk.Label(self, text="License: GNU/GPL3.0:")
        label_license_header.pack()
        label_license_github = tk.Label(self, text="https://github.com/kaotickj/KMap/blob/main/LICENSE",
                                        font=("TkDefaultFont", 10), fg="blue", cursor="hand2")
        label_license_github.pack(pady=10)
        label_license_github.bind("<Button-1>", self.on_license_github_clicked)

    def on_github_clicked(self, event):
        webbrowser.open_new("https://github.com/kaotickj/KMap/")

    def on_license_github_clicked(self, event):
        webbrowser.open_new("https://github.com/kaotickj/KMap/blob/main/LICENSE")


class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.geometry("960x780+100+100")
        self.create_widgets()

    def create_widgets(self):
        menubar = tk.Menu(self.master)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open", command=self.open_file)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self.master.quit)
        menubar.add_cascade(label="File", menu=filemenu)
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=self.about)
        menubar.add_cascade(label="Help", menu=helpmenu)
        self.master.config(menu=menubar)

    def open_file(self):
        # open file dialog
        #        file_path = filedialog.askopenfilename()
        file_path = filedialog.askopenfilename(filetypes=[("Nmap Files", "*.nmap")])

        # display file contents
        with open(file_path, 'r') as f:
            file_contents = f.read()

        text.config(state="normal")
        text.delete("1.0", "end")
        text.insert("end", f"{file_contents}", ('margin',))
        #        os.system(f"cat '{file_path}'")
        text.config(state="disabled")

    def about(self):
        dialog = AboutDialog(self.master)


#        dialog.show()

def validate_ip_address(ip_address):
    # Validate input as IP address or hostname
    if re.match(
            '^(([01]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?$',
            ip_address) or re.match(
            '^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.[a-zA-Z]{2,}$', ip_address):
        return True
    else:
        return False


class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        self.id = None
        self.x = self.y = 0

    def showtip(self):
        "Display the tooltip"
        self.tip = tk.Toplevel(self.widget)
        self.tip.attributes('-topmost', True)
        self.tip.overrideredirect(True)
        self.tip.withdraw()
        label = ttk.Label(self.tip, text=self.text, justify=tk.LEFT,
                          background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                          font=("tahoma", "11", "normal"))
        label.pack(ipadx=1)
        self.tip.update_idletasks()
        self.tipwidth = self.tip.winfo_reqwidth()
        self.tipheight = self.tip.winfo_reqheight()
        self.x = self.widget.winfo_rootx() + self.widget.winfo_width()
        self.y = self.widget.winfo_rooty() + self.widget.winfo_height()
        self.tip.geometry("+{}+{}".format(self.x, self.y))
        self.tip.deiconify()

    def hidetip(self):
        "Hide the tooltip"
        if self.tip:
            self.tip.withdraw()
            self.tip.destroy()
            self.tip = None


def create_tooltip(widget, text):
    tip = ToolTip(widget, text)

    def enter(event):
        tip.showtip()

    def leave(event):
        tip.hidetip()

    widget.bind('<Enter>', enter)
    widget.bind('<Leave>', leave)


def start_scan():
    ip_address = ip_address_entry.get()
    verbosity = verbosity_choice.get()
    scan_type = scan_type_choice.get()
    timing_option = timing_option_choice.get()
    nmap_script_option = nmap_script_options_choice.get()
    is_aggressive = is_aggressive_scan.get()
    if is_aggressive:
        aggressive_scan_options = "-A -O"
        aggressive_notice = f"** NOTICE:\nAggressive service and OS Detection Enabled: This WILL take a long time.\n\n"
    else:
        aggressive_scan_options = ""
        aggressive_notice = ""
    saving_scan = save_scan.get()
    if saving_scan:
        out_file = output_entry.get()
        save_option = f"-oN {out_file}"
    else:
        save_option = ""
    port_option = port_option_choice.get()
    port_option_range = port_option_range_entry.get()
    if port_option_range_entry.get():
        if validate_port_input(port_option_range):
            port_option_range = port_option_range_choice + port_option_range_entry.get()
        else:
            messagebox.showerror("Error",
                                 f"Not a valid entry, \"{port_option_range}\". Please enter a valid port, range of "
                                 f"ports or comma separated list of ports.")
            return
    else:
        port_option_range = ""
    addt_args = addt_args_entry.get()
    if not validate_ip_address(ip_address):
        messagebox.showerror("Error", f"Not a valid entry, \"{ip_address}\". Please enter a valid ip address or "
                                      f"domain to scan.")
        return

    command = f"nmap {verbosity} {scan_type} {addt_args} {timing_option} {port_option} {port_option_range} {nmap_script_option} {aggressive_scan_options} {save_option} {ip_address}"
    #    print(f"{command}")
    text.config(state="normal")
    text.delete("1.0", "end")
    text.insert("end", f"Command: {command}\n\n{aggressive_notice}Scan Started.  Please wait...\n\n", ('margin',))
    text.update()
    process = os.popen(command)  # Run nmap command using os.popen
    output = process.read()  # Read the output of nmap command
    process.close()  # Close the nmap process
    text.insert("end", output, ('margin',))  # Insert the output into the Text widget
    text.config(state="disabled")

    #    os.system(command)
    if save_scan.get():
        save_note = f"Output saved to {out_file}"
    else:
        save_note = ""
    messagebox.showinfo("Scan Complete", f"Scan has completed. {save_note} ")


root = tk.Tk()
root.title(f"KMap v {version}")
root.rowconfigure(0, weight=1)
root.rowconfigure(1, weight=3)
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=3)
# root.resizable(False, False)

app = Application(master=root)


# Set up the IP address entry field
ip_address_label = ttk.Label(root, text="IP address or hostname to scan:")
ip_address_label.grid(column=1, row=0, sticky="W", padx=5, pady=5)
ip_address_entry = ttk.Entry(root)
# ip_address_entry.insert(0, "scanme.org")
ip_address_entry.grid(column=1, row=0, padx=5, pady=5)

# Set up the options frame
options_frame = ttk.LabelFrame(root, text="Scan Options")
options_frame.grid(column=0, row=1, columnspan=2, padx=5, pady=5)

# Set up the verbosity options
verbosity_choice = tk.StringVar(value="")
verbosity_options = [
    {"text": "Normal Output", "value": ""},
    {"text": "Verbose Output", "value": "-v"},
    {"text": "Very Verbose Output", "value": "-vv"}
]
# Create a frame to group the verbosity options
verbosity_options_frame = ttk.LabelFrame(options_frame, text="Output Options")
verbosity_options_frame.grid(column=0, row=0, padx=5, pady=5)
# Add a label and radiobutton for each verbosity option
for i, option in enumerate(verbosity_options):
    ttk.Radiobutton(verbosity_options_frame, text=option["text"], variable=verbosity_choice,
                    value=option["value"]).grid(
        column=0, row=i, sticky="W", padx=5, pady=2)
# set up scan save options
# Set up the Save scan Checkbutton
save_scan = tk.BooleanVar()
save_scan_checkbutton = ttk.Checkbutton(verbosity_options_frame,
                                        text=" Save nmap's output?",
                                        variable=save_scan)
save_scan_checkbutton.grid(column=0, row=4, columnspan=2, padx=5, pady=2)
output_label = tk.Label(verbosity_options_frame, text="Output filename :")
output_entry = tk.Entry(verbosity_options_frame)
output_label.grid(column=0, row=5, padx=5, pady=2)
output_entry.grid(column=0, row=6, padx=5, pady=2)

# Set up the scan type radio buttons
scan_type_choice = tk.StringVar(value="")
scan_type_options = [
    {"text": "Default", "value": ""},
    {"text": "Service version scan", "value": "-sV"},
    {"text": "TCP NULL scan", "value": "-sN"},
    {"text": "TCP ACK scan", "value": "-sA"},
    {"text": "TCP FIN scan", "value": "-sF"},
    {"text": "TCP connect scan", "value": "-sT"},
    {"text": "TCP MAIMON scan", "value": "-sM"},
    {"text": "TCP WINDOW scan    ", "value": "-sW"},
    {"text": "TCP Xmas scan", "value": "-sX"},
    {"text": "UDP scan", "value": "-sU"}
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
    {"text": "Broadcast (broadcast)", "value": "--script broadcast"},
    {"text": "Bruteforce scripts (brute)", "value": "--script brute"},
    {"text": "Default scripts (default)", "value": "--script default"},
    {"text": "Exploit detection (exploit)", "value": "--script exploit"},
    {"text": "Malware scripts (malware)", "value": "--script malware"},
    {"text": "Safe scripts (safe)", "value": "--script safe"},
    {"text": "Vulnerability detection (vuln)", "value": "--script vuln"},
    {"text": "All scripts (all) (* Very Slow)", "value": "--script all"}
]
# Create a frame to group the script options
nmap_script_options_frame = ttk.LabelFrame(options_frame, text="Script Options")
nmap_script_options_frame.grid(column=1, row=1, padx=5, pady=5)
# Add a label and radiobutton for each script option
for i, option in enumerate(nmap_script_options):
    ttk.Radiobutton(nmap_script_options_frame, text=option["text"], variable=nmap_script_options_choice,
                    value=option["value"]).grid(column=1, row=i, sticky="W", padx=5, pady=2)

# Set up the timing options radio buttons
timing_option_choice = tk.StringVar(value="")
timing_option_options = [
    {"text": "Paranoid timing (-T0)", "value": "-T0"},
    {"text": "Sneaky timing (-T1)", "value": "-T1"},
    {"text": "Polite timing (-T2)", "value": "-T2"},
    {"text": "Default (normal) timing (-T3)", "value": ""},
    {"text": "Aggressive timing (-T4)", "value": "-T4"},
    {"text": "Insane timing (-T5)", "value": "-T5"}
]
# Create a frame to group the timing options
timing_option_frame = ttk.LabelFrame(options_frame, text="Timing Options")
timing_option_frame.grid(column=1, row=0, padx=5, pady=5)
# Add a label and radiobutton for each timing option
for i, option in enumerate(timing_option_options):
    ttk.Radiobutton(timing_option_frame, text=option["text"], variable=timing_option_choice,
                    value=option["value"]).grid(column=4, row=i, sticky="W", padx=5, pady=2)

# Set up the port options radio buttons
port_option_choice = tk.StringVar(value="")
port_option_options = [
    {"text": "Default", "value": ""},
    {"text": "Top 20", "value": "--top-ports 20"},
    {"text": "Top 100", "value": "--top-ports 100"},
    {"text": "Top 500", "value": "--top-ports 500"},
    {"text": "All Ports(* Very Slow)", "value": "-p-"}
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

port_option_range = ttk.Label(param_option_frame,
                              text="Specific Port, Ports, or Range\n (i.e., '22', '21,22,23', or '21-25')")
port_option_range.grid(column=0, row=0, padx=5, pady=2)
port_option_range_entry = ttk.Entry(param_option_frame)
create_tooltip(port_option_range_entry, "Note: Setting this Overrides Port Options")
port_option_range_entry.grid(column=0, row=1, padx=5, pady=5)
port_option_range_choice = "-p "

addt_args = ttk.Label(param_option_frame, text="Additional Arguments")
addt_args.grid(column=0, row=2, padx=5, pady=2)
addt_args_entry = ttk.Entry(param_option_frame)
create_tooltip(addt_args_entry,
               "For Example '-Pn' for no ping or\n enter additional scan types. Takes\n any valid nmap arguments. Use "
               "\"-h\" \n for nmap help")
addt_args_entry.grid(column=0, row=3, padx=5, pady=5)

# Set up the Aggressive scan options Checkbutton
is_aggressive_scan = tk.BooleanVar()
aggressive_scan_options_checkbutton = ttk.Checkbutton(root,
                                                      text="Enable Aggressive Scan for service and OS detection (-A -O)",
                                                      variable=is_aggressive_scan)
aggressive_scan_options_checkbutton.grid(column=0, row=3, columnspan=2, padx=5, pady=5)
create_tooltip(aggressive_scan_options_checkbutton,
               "             	   ** PLEASE NOTE: **\n Aggressive Scan is VERY slow and intrusive.")

# Output text widget
text_label = ttk.LabelFrame(options_frame, text="Output:")
text_label.grid(column=2, row=0, padx=5, pady=5, ipadx=5, ipady=5)
text = Text(options_frame, width=60, height=37)
text.config(state="disabled")
text.tag_configure('margin', lmargin1=10, lmargin2=10, rmargin=10, spacing1=0)
text.grid(column=2, row=0, rowspan=4, sticky="e", padx=5, pady=5)

# Add a button to start the scan
start_button = ttk.Button(root, text="Start Scan", command=start_scan)
start_button.grid(column=0, row=4, columnspan=2, padx=5, pady=5)

root.mainloop()