#!/usr/bin/env python
#coding:utf-8

from scapy.all import *

wifi = {}

def scan(pkt):
    if pkt.haslayer(Dot11):
        if pkt[Dot11].type == 0 and pkt[Dot11].subtype == 8:
            ap_ssid = pkt[Dot11Elt].info
            ap_mac = pkt[Dot11].addr2
            ap_channel = int(pkt[Dot11Elt][:3].info.encode('hex'))   #因为是固定位置，直接获取就行了
            if ap_ssid in wifi:
                return
            if ap_ssid =="" or ap_mac == "":
                return
            wifi[ap_ssid] = list((ap_mac, ap_channel))
            print '%-20s\t%20s\t%2s' % (ap_ssid, wifi[ap_ssid][0], wifi[ap_ssid][1])
            #sys.stdout.write('%-30s %20s\n' % (ap_ssid, ap_mac))
            
if __name__ == '__main__':
    sniff(iface='wlan0', prn=lambda x:scan(x))
    