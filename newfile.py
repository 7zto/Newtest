# device_scanner.py
import nmap
from scapy.all import ARP, Ether, srp

def scan_devices(interface="wlan0"):
    try:
        # Create ARP request packet
        arp_request = ARP(pdst="192.168.1.1/24")  # Change the subnet if needed
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        # Send and receive packets
        result = srp(arp_request_broadcast, timeout=3, verbose=False)[0]

        # Parse results
        devices = []
        for sent, received in result:
            devices.append({"ip": received.psrc, "mac": received.hwsrc})

        return devices
    except Exception as e:
        return str(e)

def get_device_type(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-O")  # Perform OS detection
        device_type = nm[ip]["osmatch"][0]["name"]
        return device_type
    except Exception as e:
        return "Unknown"

if __name__ == "__main__":
    devices = scan_devices()
    for device in devices:
        device_type = get_device_type(device["ip"])
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Device Type: {device_type}")
