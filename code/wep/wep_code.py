#/usr/bin/env python
#coding:utf-8

from scapy.all import *
import time, pickle

pkt_num = 0
def show(pkt):
    global pkt_num
    if pkt.haslayer(Dot11WEP):
        if (pkt[Dot11].addr1 == 'e4:d3:32:4b:03:9c' and pkt[Dot11].addr2 == 'f4:9f:f3:92:47:c4') or (pkt[Dot11].addr1 == 'f4:9f:f3:92:47:c4' and pkt[Dot11].addr2 == 'e4:d3:32:4b:03:9c') or (pkt[Dot11].addr1 == 'e4:d3:32:4b:03:9c' and pkt[Dot11].addr2 == 'ec:1d:7f:bc:b3:a8') or (pkt[Dot11].addr1 == 'ec:1d:7f:bc:b3:a8' and pkt[Dot11].addr2 == 'e4:d3:32:4b:03:9c'):
            print 
            print pkt_num,
            pkt_num = pkt_num+1
            pkt_iv = pkt[Dot11WEP].iv
            print pkt_iv.encode('Hex'),
            
            #write all_pkts.txt
            #f_all_pkts.write(pkt_iv.encode('Hex')+'\n')
            #f_all_pkts.flush()
            
            if pkt_iv[0] == '\x03' and pkt_iv[1] == '\xff':
                filename = './03ff_pkts/'+pkt_iv.encode('hex')
                with open(filename, 'w') as f:
                    dict = {'pkt_iv':pkt_iv, 'pkt_wepdata':pkt[Dot11WEP].wepdata}
                    pickle.dump(dict, f)
                    f.flush()
                return
            
            if pkt_iv[0] == '\x04' and pkt_iv[1] == '\xff':
                filename = './04ff_pkts/'+pkt_iv.encode('hex')
                with open(filename, 'w') as f:
                    dict = {'pkt_iv':pkt_iv, 'pkt_wepdata':pkt[Dot11WEP].wepdata}
                    pickle.dump(dict, f)
                    f.flush()          
                return
            
            if pkt_iv[0] == '\x05' and pkt_iv[1] == '\xff':
                filename = './05ff_pkts/'+pkt_iv.encode('hex')
                with open(filename, 'w') as f:
                    dict = {'pkt_iv':pkt_iv, 'pkt_wepdata':pkt[Dot11WEP].wepdata}
                    pickle.dump(dict, f)
                    f.flush()      
                return
        
            if pkt_iv[0] == '\x06' and pkt_iv[1] == '\xff':
                filename = './06ff_pkts/'+pkt_iv.encode('hex')
                with open(filename, 'w') as f:
                    dict = {'pkt_iv':pkt_iv, 'pkt_wepdata':pkt[Dot11WEP].wepdata}
                    pickle.dump(dict, f)
                    f.flush()                  
                return
        
            if pkt_iv[0] == '\x07' and pkt_iv[1] == '\xff':
                filename = './07ff_pkts/'+pkt_iv.encode('hex')
                with open(filename, 'w') as f:
                    dict = {'pkt_iv':pkt_iv, 'pkt_wepdata':pkt[Dot11WEP].wepdata}
                    pickle.dump(dict, f)
                    f.flush()
                return
            
def main():
    while(True):
        try:
            sniff(iface='wlan0', prn=lambda x:show(x))
        except BaseException, e:
            print e
            time.sleep(10)
    

if __name__ == '__main__':
    main()