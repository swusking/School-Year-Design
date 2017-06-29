#!/usr/bin/env python
#coding:utf-8

import pickle, os
'''
key3: 18
key4: 52
key5: 86
key6: 120
key7: 144
'''


def get_key3(pkt):
    first_key = ord(pkt['pkt_wepdata'][0]) ^ 0xaa 
    pkt_iv = pkt['pkt_iv']
    
    #print pkt_iv.encode('hex')
    key = pkt_iv + '\x00\x00\x00\x00\x00'
    
    statu_v = range(256)
    temp_v = [ ord( key[i % len(key)] )for i in range(256)]
    #print statu_v
    #print temp_v
    
    #KSA
    j = 0
    for i in range(3):
        j = (j + statu_v[i] + temp_v[i]) % 256
        statu_v[i], statu_v[j] = statu_v[j], statu_v[i]

    
    # j3 = 6 + x + K[3]
    index = statu_v.index(first_key)
    for i in range(256):
        if index == (6 + ord(pkt_iv[2]) + i) % 256:
            return i
    


def get_key4(pkt):
    first_key = ord(pkt['pkt_wepdata'][0]) ^ 0xaa 
    pkt_iv = pkt['pkt_iv']
    
    #print pkt_iv.encode('hex')
    key = pkt_iv + '\x12\x00\x00\x00\x00'
    
    statu_v = range(256)
    temp_v = [ ord( key[i % len(key)] )for i in range(256)]
    #print statu_v
    #print temp_v
    
    #KSA
    j = 0
    for i in range(4):
        j = (j + statu_v[i] + temp_v[i]) % 256
        statu_v[i], statu_v[j] = statu_v[j], statu_v[i]

    
    # j4 = 28 + x + K[4]
    index = statu_v.index(first_key)
    for i in range(256):
        if index == (28 + ord(pkt_iv[2]) + i) % 256:
            return i



def get_key5(pkt):
    first_key = ord(pkt['pkt_wepdata'][0]) ^ 0xaa 
    pkt_iv = pkt['pkt_iv']
    
    #print pkt_iv.encode('hex')
    key = pkt_iv + '\x12\x34\x00\x00\x00'
    
    statu_v = range(256)
    temp_v = [ ord( key[i % len(key)] )for i in range(256)]
    #print statu_v
    #print temp_v
    
    #KSA
    j = 0
    for i in range(5):
        j = (j + statu_v[i] + temp_v[i]) % 256
        statu_v[i], statu_v[j] = statu_v[j], statu_v[i]

    
    # j5 = 85 + x + K[5]
    index = statu_v.index(first_key)
    for i in range(256):
        if index == (85 + ord(pkt_iv[2]) + i) % 256:
            return i

def get_key6(pkt):
    first_key = ord(pkt['pkt_wepdata'][0]) ^ 0xaa 
    pkt_iv = pkt['pkt_iv']
    
    #print pkt_iv.encode('hex')
    key = pkt_iv + '\x12\x34\x56\x00\x00'
    
    statu_v = range(256)
    temp_v = [ ord( key[i % len(key)] )for i in range(256)]
    #print statu_v
    #print temp_v
    
    #KSA
    j = 0
    for i in range(6):
        j = (j + statu_v[i] + temp_v[i]) % 256
        statu_v[i], statu_v[j] = statu_v[j], statu_v[i]

    
    # j6 = 177 + x + K[6]
    index = statu_v.index(first_key)
    for i in range(256):
        if index == (177 + ord(pkt_iv[2]) + i) % 256:
            return i



def get_key7(pkt):
    first_key = ord(pkt['pkt_wepdata'][0]) ^ 0xaa 
    pkt_iv = pkt['pkt_iv']
    
    #print pkt_iv.encode('hex')
    key = pkt_iv + '\x12\x34\x56\x78\x00'
    
    statu_v = range(256)
    temp_v = [ ord( key[i % len(key)] )for i in range(256)]
    #print statu_v
    #print temp_v
    
    #KSA
    j = 0
    for i in range(7):
        j = (j + statu_v[i] + temp_v[i]) % 256
        statu_v[i], statu_v[j] = statu_v[j], statu_v[i]

    
    # j7 = 304 + x + K[7]
    index = statu_v.index(first_key)
    for i in range(256):
        if index == (304 + ord(pkt_iv[2]) + i) % 256:
            return i


def main():
    key3_temp = {}  # 存储key3可能的结果，并统计出字数
    key3_filenames = os.listdir('03ff_pkts')
    #print file
    for filename in key3_filenames:
        with open('./03ff_pkts/'+filename, 'r') as f:
            pkt = pickle.load(f)
            key = get_key3(pkt)
            if key in key3_temp:
                key3_temp[key] += 1
            else:
                key3_temp[key] = 1
    
    print 'key3_temp: ', key3_temp
    
####################################    
    key4_temp = {}
    key4_filenames = os.listdir('04ff_pkts')
    for filename in key4_filenames:
        with open('./04ff_pkts/'+filename, 'r') as f:
            pkt = pickle.load(f)
            key = get_key4(pkt)
            if key in key4_temp:
                key4_temp[key] += 1
            else:
                key4_temp[key] = 1
    
    print 'key4_temp: ', key4_temp

################################
    key5_temp = {}
    key5_filenames = os.listdir('05ff_pkts')
    for filename in key5_filenames:
        with open('./05ff_pkts/'+filename, 'r') as f:
            pkt = pickle.load(f)
            key = get_key5(pkt)
            if key in key5_temp:
                key5_temp[key] += 1
            else:
                key5_temp[key] = 1
    
    print 'key5_temp: ', key5_temp


################################
    key6_temp = {}
    key6_filenames = os.listdir('06ff_pkts')
    for filename in key6_filenames:
        with open('./06ff_pkts/'+filename, 'r') as f:
            pkt = pickle.load(f)
            key = get_key6(pkt)
            if key in key6_temp:
                key6_temp[key] += 1
            else:
                key6_temp[key] = 1
    
    print 'key6_temp: ', key6_temp


################################
    key7_temp = {}
    key7_filenames = os.listdir('07ff_pkts')
    for filename in key7_filenames:
        with open('./07ff_pkts/'+filename, 'r') as f:
            pkt = pickle.load(f)
            key = get_key7(pkt)
            if key in key7_temp:
                key7_temp[key] += 1
            else:
                key7_temp[key] = 1
    
    print 'key7_temp: ', key7_temp
    
    
if __name__ == '__main__':
    main()