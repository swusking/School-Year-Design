#!/usr/bin/env python
#coding:utf-8

from scapy.all import *
import sys, hashlib, hmac
import pbkdf2, prf512, ccmp, tpik

pkts_number = 0
ANonce = '' 
SNonce = ''
MIC = ''
DATA = ''

def show(pkt, ap_mac, sta_mac):
    global ANonce, SNonce, pkts_number, MIC, DATA
    pkts_number = pkts_number + 1
    sys.stdout.write('\rpakets: %d' % pkts_number)
    if pkt.haslayer(EAPOL):
        if pkt[Dot11].addr1 == sta_mac and pkt[Dot11].addr2 == ap_mac:        
            if ANonce == '':
                ANonce = str(pkt)[87:119].encode('hex')
            if SNonce != '':
                return True             
            
        if pkt[Dot11].addr1 == ap_mac and pkt[Dot11].addr2 == sta_mac:
            if SNonce == '':
                string =  str(pkt)
                SNonce = string[87:119].encode('hex')      #获取了第二个随机数直接终止抓取
                MIC = string[151:167].encode('hex')   
                DATA = string[70:151].encode('hex') + '00000000000000000000000000000000' + string[167:193].encode('hex')
            if ANonce != '':
                return True 
        
def get_shark(ap_mac, sta_mac, mode):
    print 'Geting...'
    try:     #把数据全部传给show处理，如果得到了ANonce和SNonce就停止抓包
        sniff(iface='wlan0', stop_filter=lambda x:show(x, ap_mac, sta_mac))
    except BaseException, e:
        print e
    
    print
    print 'ANonce: ', ANonce
    print 'SNonce: ', SNonce
    print 'MIC: ', MIC
    print 'DATA: ', DATA 
    
    PASSOWRD = '1234567890'
    SSID = 'Sking'
    AP_MAC = ''.join(ap_mac.split(':'))
    STA_MAC = ''.join(sta_mac.split(':'))
    
    #print AP_MAC
    #print STA_MAC
    print
    print 'Get: ', 
    #WPA2
    if mode == 'ccmp':
        print ccmp.get_mic(PASSOWRD, SSID, AP_MAC, STA_MAC, ANonce, SNonce, DATA)
    #WPA
    if mode == 'tpik':
        print tpik.get_mic(PASSOWRD, SSID, AP_MAC, STA_MAC, ANonce, SNonce, DATA)
    
if __name__ == '__main__':
    ap_mac = sys.argv[1]   #AP:e4:d3:32:4b:03:9c
    sta_mac = sys.argv[2]  #STA:f4:9f:f3:92:47:c4
    mode = sys.argv[3]
    get_shark(ap_mac, sta_mac, mode)