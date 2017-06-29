#!/usr/bin/env python
#coding:utf-8

from scapy.all import *
import hashlib, hmac
import kdf

'''
p = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF'
q = 2

[95]
M1:0x04
M2:0x05
M3:0x07
M4:0x08
WSC_NACK:0x0e
'''

pkt_M1 = None

def show(pkt):
    global pkt_M1
    if pkt.haslayer(EAP):
        if pkt[EAP].type == 254:
            if ord(str(pkt)[95]) == 4:
                pkt_M1 = pkt
                return True

def wps():
    sta_mac = '52:67:0d:43:2e:5f'
    
    #Dot11Deauth
    pkt_Deauth = RadioTap() \
        / Dot11(subtype=0x0c, type=0, addr1='E4:D3:32:4B:03:9C', addr2=sta_mac, addr3='E4:D3:32:4B:03:9C', SC=0x0010)\
        / Dot11Deauth(reason=3)
    
    sendp(pkt_Deauth, iface='wlan0')
    
    #Dot11Auth
    pkt_Auth = RadioTap() \
        / Dot11(subtype=0x0b, type=0, addr1='E4:D3:32:4B:03:9C', addr2=sta_mac, addr3='E4:D3:32:4B:03:9C', SC=0x0020)\
        / Dot11Auth(seqnum=1)
    
    sendp(pkt_Auth, iface='wlan0')
    
    
    #Dot11AssoReq
    pkt_AssocReq = RadioTap() \
        / Dot11(subtype=0x00, type=0, addr1='E4:D3:32:4B:03:9C', addr2=sta_mac, addr3='E4:D3:32:4B:03:9C', SC=0x0030)\
        / Dot11AssoReq(cap=0x3140) \
        / Dot11Elt(ID=0, info='Sking') \
        / Dot11Elt(ID=1, info='82848b960c121824'.decode('hex')) \
        / Dot11Elt(ID=50, info='3048606c'.decode('hex')) \
        / Dot11Elt(ID=221, info='0050f204104a000110103a000102'.decode('hex'))
    
    
    sendp(pkt_AssocReq, iface='wlan0')
    
    '''--------------------------------------'''
    
    #EAPOL
    pkt_EAPOL = RadioTap() \
        / Dot11(subtype=0x00, type=2, FCfield=0x01, addr1='E4:D3:32:4B:03:9C', addr2=sta_mac, addr3='E4:D3:32:4B:03:9C', SC=0x0040)\
        / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
        / SNAP(OUI=0x0, code=0x888e)  \
        / EAPOL(version=1, type=1)
    
    sendp(pkt_EAPOL, iface='wlan0')

    #EAP Identity
    pkt_EAPOL_ID = RadioTap() \
        / Dot11(subtype=0x00, type=2, FCfield=0x01, addr1='E4:D3:32:4B:03:9C', addr2=sta_mac, addr3='E4:D3:32:4B:03:9C', SC=0x0050)\
        / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
        / SNAP(OUI=0x0, code=0x888e)  \
        / EAPOL(version=1, type=0) \
        / EAP(code=2, id=0, type=1, identity='WFA-SimpleConfig-Registrar-1-0')  
    #这个ID不用对应，好像就是0开始
    sendp(pkt_EAPOL_ID, iface='wlan0')
    
    #抓到M1包停止
    sniff(stop_filter=lambda x:show(x), iface='wlan0')

    pkt_M1_str = str(pkt_M1)
    M1_id = ord(pkt_M1_str[73])
    M1_Enrollee_Nonce = pkt_M1_str[130:146]
    M1_Public = pkt_M1_str[150:342]
    M1_Enrollee_MAC = pkt_M1_str[120:126]
    #print M1_Public.encode('hex')
    
    
    #EAP M2
    pkt_EAP_M2 = RadioTap() \
        / Dot11(subtype=0x00, type=2, FCfield=0x01, addr1='E4:D3:32:4B:03:9C', addr2=sta_mac, addr3='E4:D3:32:4B:03:9C', SC=0x0060) \
        / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
        / SNAP(OUI=0x0, code=0x888e)  \
        / EAPOL(version=1, type=0, len=383) \
        / EAP(code=2, id=M1_id, type=254, len=383)
    
    #######################构建数据包
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
    g = 2    
    A = 2100
    #M2_Publick = (g**A) % p  #已经计算好了，反正都是实验
    M2_Public = 'e9a5475db33db7b80991b6c601ec9cf461abe604a767bd9f8d60c333341013b31645be5c59ec770aa04e873afdb8b0f170968e2a5532436ec17c52d245e11a32146830febc5aea577aae3f129eca41ba8f3d1e5153f3d0a6217b877f58f0cce01edab961a5f09adfdc5d53e5ebba5ba71f1acc18be09ff60ff0b377d91272d70b606cf2784d6484bafc1721828fc14f5a02a379048a6656c3e58be1ac5335309b0c2326daef866fd4497fc0288ad0fc0153ae1660f5dd9b550dc8c9d3d922eec'.decode('hex')
    M2_Registrar_Nonce = 'f6c07d16a13a84a7145fcb1bf4b3f672'.decode('hex')
    DHKey_int = ( int(M1_Public.encode('hex'), 16) ** A ) % p
    #print DHKey_int
    
    print len(hex(DHKey_int)[2:-1].decode('hex')) #打印一下长度，官方文档说不足192要补0，好累
    
    DHKey = hashlib.sha256(hex(DHKey_int)[2:-1].decode('hex')).digest()
    print "DHKey: ", DHKey.encode('hex')
    
    KDK = hmac.new(DHKey, M1_Enrollee_Nonce + M1_Enrollee_MAC + M2_Registrar_Nonce, hashlib.sha256).digest()
    print "KDK: ", KDK.encode('hex')
    
    Key = kdf.kdf(KDK, 'Wi-Fi Easy and Secure Key Derivation', 640)
    print 'Key: ', Key.encode('hex')
    
    #得到三种密钥
    AuthKey = Key[:32]
    KeyWrapKey = Key[32:48]
    EMSK = Key[48:]
    
    data = '00372a000000010400104a0001101022000105101a0010a33a172cd92d13d1372122821760681710390010f6c07d16a13a84a7145fcb1bf4b3f672104800101bd764bb429ee03c57ccc1657397809d103200c0e4826d2e9652ac08ac46b9c28ba2a3f3735124bbfdd8790c995fae4f45de53fd98d3a4446fae71eaff71f36d622987048e576ce6b7c63eeaeeb08e3ea50c67e7dcf12c650d3b9d962a83551b3d754044c04946df8eba1802f2d49e3e901d092346a11ea25fefde2cc94d7da55464646e52670eb28839c971ef48f1f250f0612e35adb97a63fe64689cda1464ebbd771ca4b442dc584adcc535c2853fde235a128c223f1b68202f212111fcc0364ed41d50f1c91de1066d0bdad9b6744493669010040002003f10100002000f100d00010110080002008c10210001001023000100102400010010420001001054000800000000000000001011000100103c000100100200020000100900020000101200020000102d0004800000001005000862f79835768de1dc'.decode('hex')
    data = data[:23] + M1_Enrollee_Nonce + data[39:83] + M2_Public + data[275:-8] + '0000000000000000'.decode('hex')
    
    #计算M1||M2*
    Authenticator = hmac.new(AuthKey, pkt_M1_str + str(pkt_EAP_M2) + data, hashlib.sha256).digest()[:8]
    print 'Auth: ', Authenticator.encode('hex')
    
    data = data[:-8] + Authenticator
    #######################
    
    pkt_EAP_M2_str = str(pkt_EAP_M2)
    pkt_EAP_M2_str = pkt_EAP_M2_str + data
    pkt_EAP_M2 = RadioTap(pkt_EAP_M2_str)
    
    sendp(pkt_EAP_M2, iface='wlan0')

if __name__ == '__main__':
    #main()
    wps()