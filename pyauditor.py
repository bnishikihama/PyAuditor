"""
PyAuditor
Major Project - COMP 8047
Author: Braeden Nishikihama A01046511
"""

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.all import *
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tkinter import *
import subprocess
import queue
import logging
import threading

import settings


# Logging
logging.basicConfig(
    filename="log.txt",
    filemode="a+",
    format='%(asctime)s - %(levelname)s - %(message)s'
)
log = logging.getLogger(__name__)
# Get current IP address
CURR_IP = get_if_addr(settings.interface)


def protocol_ck(pkt):
    """
    Checks if the protocol is enabled in the settings. If enabled, compares the payload of the packet with the commonly
    found protocol keywords;
    :param pkt: Incoming TCP packet to be checked
    :return: String of protocol
    """
    global packet_queue
    protocol = settings.target_protocols

    # Return if no TCP
    if not pkt.haslayer("TCP"):
        return

    # Set payload from packet payload
    payload = bytes(pkt["TCP"].payload)
    # If payload is empty, return
    if payload == b"":
        return

    if pkt.haslayer("IP"):
        ip_desc = f"({pkt[IP].dst}:{pkt[TCP].dport}  <--  {pkt[IP].src}:{pkt[TCP].sport}"
    else:
        ip_desc = f"({pkt[IPv6].dst}:{pkt[TCP].dport}  <--  {pkt[IPv6].src}:{pkt[TCP].sport}"

    # Check payload for SSH keyword.
    # In Fedora36, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" shows
    if protocol["ssh"]:
        if b"SSH" in payload:
            return "SSH Payload Detected"

    # Check payload for telnet keywords
    if protocol["telnet"]:
        if (b"telnet" in payload.lower()) or (b"login:" in payload.lower()) or (b"password:" in payload.lower()):
            return "Telnet Payload Detected"

    # Check payload for FTP keywords
    if protocol["ftp"]:
        if b"FTP" in payload:
            return "FTP Connection Detected"

    # Check payload for HTTP keywords
    if protocol["http"]:
        if (b"GET" in payload) or (b"POST" in payload) or (b"HEAD" in payload) or (b"PUT" in payload) \
                or (b"DELETE" in payload) or (b"CONNECT" in payload) or (b"HTTP" in payload):
            packet_queue.put(f"HTTP Payload Detected")
            packet_queue.put(ip_desc)
            packet_queue.put("")
            root.after(0, update_gui)
            return

    return


def secret_message_ck(pkt):
    """
    Check if there are keywords in the payload of packets. For example, checks if the bytestring "secret" is in the
    payload;
    :param pkt: Incoming TCP packet to be checked
    :return: String of identified secret message
    """
    keywords = settings.keywords

    if not pkt.haslayer("TCP"):
        return
    # Set payload from packet payload
    payload = bytes(pkt["TCP"].payload)
    # If payload empty, skip
    if payload == b"":
        return
    # Check if payload contains a keyword
    for keyword in keywords:
        if keyword.encode("utf-8") in payload:
            return f"Keyword: {keyword} in Payload"


def sequence_num_ck(pkt):
    """
    Checks if the incoming packet has a sequence number that has already occurred a number of times;
    Threshold of number of duplicate sequence numbers is located in settings.num_seq_dup;
    Naive implementation of checking for sequence number;
    :param pkt: Incoming TCP packet to be checked
    :return: None
    """
    global seq_history

    if pkt.haslayer("IP"):
        if pkt.haslayer("TCP"):
            src_ip = pkt["IP"].src
            seq_num = pkt["TCP"].seq

            # If list empty, add packet
            if not seq_history:
                seq_history.append({
                    "ip": src_ip,
                    "seq_count": {seq_num: 1}
                })
                return

            # Check if the seq exists in that IPs history
            for p in seq_history:
                if p["ip"] == src_ip:
                    if seq_num in p["seq_count"]:
                        if p["seq_count"][seq_num] >= settings.num_seq_dup:
                            p["seq_count"][seq_num] += 1
                            packet_queue.put(f"Too many duplicate Sequence Numbers. " 
                                             f"seq={seq_num}(count={p['seq_count'][seq_num]})")
                            packet_queue.put("")
                            root.after(0, update_gui)
                            return
                        # Seq exists
                        p["seq_count"][seq_num] += 1
                        return
                    else:
                        p["seq_count"].update({seq_num: 1})
                        return
            # IP does not exist in seq_history
            seq_history.append({
                "ip": src_ip,
                "seq_count": {seq_num: 1}
            })
            return


def flag_ck(pkt):
    """
    Checks if the incoming packet violates any of the stored flag rules;
    :param pkt: Incoming TCP packet to be checked
    :return: String of rule violation if rule was violated; None if rule was not violated
    """
    if pkt.haslayer("TCP"):
        tcp_pkt = pkt["TCP"]
        # Check if no flags set
        if tcp_pkt.flags == 0x00:
            return "No Flag Bits Set"
        # Check if ACK flag set and ack num is 0 (TCP Scan)
        if tcp_pkt.flags == 0x10 and tcp_pkt.ack == 0:
            return "Probable TCP Scan (ACK Bit Set and ack_num = 1"
        # Check if XMAS flags (URG, FIN, PSH)
        if tcp_pkt.flags == 0x029:
            return "XMas Bits Set (URG, FIN, PSH)"
        # Check if Hping3 xmas (unused flag - different from standard Xmas flags)
        if tcp_pkt.flags == 0x40:
            return "X Unused Flag Bit Set"
        # Check if Hping3 ymas (unused flag)
        if tcp_pkt.flags == 0x80:
            return "Y Unused Flag Bit Set"
    return


def port_ck(pkt):
    """
    Checks if the destination of the packet is a warned port for this machine;
    :param pkt: Incoming TCP packet to be checked
    :return: String of rule violation if rule was violated;
    None if rule was not violated
    """
    if pkt['TCP'].dport in settings.target_ports:
        return "Port Rule"
    return


def ip_whitelist(pkt):
    """
    Checks if packet should be ignored or not; Dependent on settings.whitelist_ip
    :param pkt: Incoming TCP packet to be checked
    :return: True if IP is in settings.whitelist_ip;
    False if IP not in settings.whitelist_ip
    """
    if pkt["IP"].src in settings.whitelist_ip:
        return True
    return False


def port_whitelist(pkt):
    """
    Checks blacklisted ports. These ports are ignored in warnings
    :param pkt: Packet to check if it has blacklisted ports
    :return: True if port blacklisted;
    False if not
    """
    if pkt['TCP'].dport in settings.whitelist_ports:
        return True
    return False


def is_malicious(pkt):
    """
    Checks if Packet is malicious;
    Ignored if port or IP is whitelisted in settings
    :param pkt: Incoming TCP packet to be checked
    :return: Message list that contains all the rule violations, if any
    """
    global seq_history

    message = []

    if pkt.haslayer('IP'):
        if pkt.haslayer('TCP'):
            # Ignore if IP is whitelisted
            if ip_whitelist(pkt):
                return message

            # Check for sequence number violation
            sequence_num_ck(pkt)

            # Check Flags
            f_ck = flag_ck(pkt)
            if f_ck is not None:
                message.append(f_ck)

            s_ck = secret_message_ck(pkt)
            if s_ck is not None:
                message.append(s_ck)

            # Check Protocol
            pr_ck = protocol_ck(pkt)
            if pr_ck is not None:
                message.append(pr_ck)

            # Check if port is whitelisted,
            if port_whitelist(pkt):
                return message

            # Check ports
            p_ck = port_ck(pkt)
            if p_ck is not None:
                message.append(p_ck)

    return message


def pkt_callback(pkt):
    """
    The function that handles a packet that was sniffed;
    :param pkt: Incoming TCP packet to be checked
    :return: None
    """
    global packet_queue, num_packets

    try:
        src_ip = pkt["IP"].src

        # Check if packet is blocked first
        if src_ip in blocked_ips:
            return

        # Determine which rule violations the packet tripped
        message = is_malicious(pkt)

        # Calculate and update Line Plot
        throughput.append(len(pkt))
        timestamps.append(time.time() - start_time)
        ax2.plot(timestamps, throughput, color="red")

        if message:
            if pkt.haslayer("TCP"):
                num_packets += 1

                # Packet violated a rule. Check if it should be blocked
                if src_ip in past_infractions:
                    if past_infractions[src_ip] >= settings.ban_threshold:
                        # Run iptables command to drop all packets from this IP
                        block_ip(src_ip)
                        # Add this IP to blocked list
                        blocked_ips.append(src_ip)
                        # Log block
                        block_message = f"Blocked IP: {src_ip}"
                        log.critical(block_message)
                        packet_queue.put("======================")
                        packet_queue.put(block_message)
                        packet_queue.put("======================")
                        packet_queue.put("")
                        root.after(0, update_gui)
                        return

                if pkt.haslayer("IP"):
                    ip_desc = f"({num_packets}) {pkt[IP].dst}:{pkt[TCP].dport}  <--  {pkt[IP].src}:{pkt[TCP].sport}"
                else:
                    ip_desc = f"({num_packets}) {pkt[IPv6].dst}:{pkt[TCP].dport}  <--  {pkt[IPv6].src}:{pkt[TCP].sport}"

                # Log rule violation
                log.warning(ip_desc)
                for i in message:
                    packet_queue.put(i)
                packet_queue.put(ip_desc)
                packet_queue.put("")
                root.after(0, update_gui)

                # Update the number of rule violations by IP
                if src_ip in past_infractions:
                    past_infractions[src_ip] += 1
                else:
                    past_infractions[src_ip] = 1

                # Update Bar Graph
                ax1.bar(past_infractions.keys(), past_infractions.values(), color="cornflowerblue")
                canvas.draw()

            else:
                log.debug(pkt)

    except IndexError as e:
        print("Tripped IndexError")
        print(e)
        print(pkt.summary())


def sniff_pkt():
    """
    Sniffs packets. Returns filtered packets to pkt_callback()
    :return: None
    """
    try:
        global thread_running
        thread_running = True
        packet_queue.put("Sniffing...")
        packet_queue.put("====================")
        root.after(0, update_gui)
        sniff(iface=settings.interface, prn=pkt_callback, filter=f"tcp and dst host {CURR_IP}", store=0)
        thread_running = False
    except OSError:
        print("OSError: Incorrect Interface")
        thread_running = False
        root.destroy()


def update_gui():
    """
    Updates the listbox and displays all packets that violated rules
    :return: None
    """
    global packet_queue
    while not packet_queue.empty():
        output = packet_queue.get()
        packet_list.insert(END, output)
        packet_list.yview(END)


def update_plt():
    """
    Updates Line Plot;
    :return: None
    """
    global timestamps, throughput
    line.set_data(timestamps, throughput)
    ax2.relim()
    ax2.autoscale_view()


def block_ip(ip):
    """
    Uses iptables command to DROP all packets from IP;
    Writes iptables rule and executes save_iptables();
    :param ip: Source IP of packet to be blocked with iptables
    :return: None
    """
    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    returncode = process.wait()
    if returncode != 0:
        print(f"Error: iptables-save failed with return code {returncode}: {process.stderr.read().decode()}")
    # Save changes to iptables to the iptables_rules.txt file
    save_iptables()


def save_iptables():
    """
    Updates the iptables_rules.txt with current iptables rules;
    :return: None
    """
    try:
        with open("iptables_rules.txt", "w") as f:
            process = subprocess.Popen(["iptables-save"], stdout=f, stderr=subprocess.PIPE, shell=True)
            returncode = process.wait()
            if returncode != 0:
                print(f"Error: iptables-save failed with return code {returncode}: {process.stderr.read().decode()}")
    except FileNotFoundError:
        print("Unable to save iptables rules at \"iptables_rules.txt\".")


def handle_iptables():
    """
    Retrieves dropped IPs from iptables_rules.txt to populate blocked_ips list;
    If no IPs are retrieved, no prior blocked IPs are considered;
    Runs once on startup;
    :return: None
    """
    global blocked_ips
    try:
        with open("iptables_rules.txt", "r") as f:
            process = subprocess.Popen(["iptables-restore"],
                                       stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            returncode = process.wait()
            if returncode != 0:
                print(f"Error: iptables-restore failed with return code {returncode}: {process.stderr.read().decode()}")
    except FileNotFoundError:
        print("Unable to load iptables rules from \"iptables_rules.txt\".")
        print("iptables rules have been reset.")

    cmd = "iptables -L INPUT -v -n | grep DROP | awk '{print $8}'"
    iptables_output = subprocess.check_output(cmd, shell=True).decode()
    a = iptables_output.strip().split("\n")
    for ips in a:
        blocked_ips.append(ips)


def main():
    """
    Spawns thread for packet sniffing
    """
    global thread_running
    if not thread_running:
        thread = threading.Thread(target=sniff_pkt, daemon=True)
        thread.start()


# Set GUI window
root = Tk()
root_width, root_height = root.winfo_screenwidth(), root.winfo_screenheight()
root.geometry(f"{root_width}x{root_height}+0+0")
root.title("PyAuditor")

# GLOBAL VARIABLES
# List of blocked IPs retrieved from iptables and those added during execution
blocked_ips = []
# The IPs tied to how many rules they have tripped in current program history
past_infractions = {}
# The sequence number history of a given IP
seq_history = []
# List of packet sizes for Line Plot
throughput = []
# List of timestamps for Line Plot
timestamps = []
# Start time for elapsed time calculation
start_time = time.time()

# Create the two subplots for Bar Graph and Line Plot
fig, (ax1, ax2) = plt.subplots(nrows=1, ncols=2)
fig.set_figwidth(15)
fig.tight_layout(pad=5.0)
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack()
# Create Line Plot
line, = ax2.plot([], [], lw=2)

# Labels for Bar Graph
ax1.set_xlabel("Source IP")
ax1.set_ylabel("Number of Infractions")
ax1.set_title("Total of Infractions by IP")

# Labels for Line Plot
ax2.set_xlabel("Time (s)")
ax2.set_ylabel("Size of Packet (bytes)")
ax2.set_title("Throughput (bytes) per Second")

# Listbox for storing packets that trip a rule
packet_list = Listbox(root, width=root_width, height=12)
packet_list.pack()

total_bytes = 0
thread_running = False
packet_queue = queue.Queue()
num_packets = 0

handle_iptables()

start_button = Button(root, text="Start Sniffing", command=main)
start_button.pack()

# Run the main loop
root.mainloop()
