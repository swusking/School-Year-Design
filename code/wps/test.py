#!/usr/bin/env python
#coding:utf-8

from scapy.all import *
import pickle, sys

'''
[95]
M1:0x04
M2:0x05
M3:0x07
M4:0x08
WSC_NACK:0x0e
'''

def show(pkt):
    if pkt.haslayer(EAP):
        if pkt[EAP].type == 254:
            if ord(str(pkt)[95]) == 4:
                with open('./M1.pkt', 'w') as f:
                    pickle.dump(str(pkt), f)
            if ord(str(pkt)[95]) == 6:
                with open('./M3.pkt', 'w') as f:
                    pickle.dump(str(pkt), f)
            if ord(str(pkt)[95]) == 0x0e:
                with open('./WSC_NACK.pkt', 'w') as f:
                    pickle.dump(str(pkt), f)
                    sys.exit(0)

def main():
    with open('./M1.pkt', 'r') as f:
        pkt = RadioTap(pickle.load(f))
        print pkt.show()
        data = str(pkt)
        print data.encode('hex')
        print 'AP_MAC: ', ':'.join( [ data[i].encode('hex') for i in range(120, 126)] )
        print 'Enrollee_Nonce: ', data[130:146].encode('hex')
        print 'AP_Publick_Key: ', data[150:342].encode('hex')
        

def dh():
    #384位
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
    g = 2
    A = 2100
    PK_Enrollee = (g**A) % p
    PK_Register = 'e4826d2e9652ac08ac46b9c28ba2a3f3735124bbfdd8790c995fae4f45de53fd98d3a4446fae71eaff71f36d622987048e576ce6b7c63eeaeeb08e3ea50c67e7dcf12c650d3b9d962a83551b3d754044c04946df8eba1802f2d49e3e901d092346a11ea25fefde2cc94d7da55464646e52670eb28839c971ef48f1f250f0612e35adb97a63fe64689cda1464ebbd771ca4b442dc584adcc535c2853fde235a128c223f1b68202f212111fcc0364ed41d50f1c91de1066d0bdad9b67444936690'
    print hex(PK_Enrollee)
    print PK_Register


if __name__ == '__main__':
    #sniff(iface='wlan0', prn=lambda x:show(x))
    #main()
    dh()