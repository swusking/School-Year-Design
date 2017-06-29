#!/usr/bin/env python
#coding:utf-8

from multiprocessing import Pool
import sys, pickle, os, time

def baoli(args):
    data = '\xaa\xaa\x03\x00\x00'
    en_data = args['en_data']
    key = args['key']


    statu_v = range(256)  #状态向量
    temp_v = [ ord(key[x % len(key)]) for x in range(256)]  #初始向量
    en_data_temp = ''  #加密的结果

    #初始化状态向量
    j = 0
    for i in xrange(256):
        j = (j + statu_v[i] + temp_v[i]) % 256
        statu_v[i], statu_v[j] = statu_v[j], statu_v[i]

    #流产生
    i=j=0
    for x in xrange(len(data)):
        i = (i + 1) % 256
        j = (j + statu_v[i]) % 256
        statu_v[i], statu_v[j] = statu_v[j], statu_v[i]
        t = (statu_v[i] + statu_v[j]) % 256
        c = chr( ord(data[x]) ^ statu_v[t] )
        if c != en_data[x]:
            return
        en_data_temp += chr( ord(data[x]) ^ statu_v[t] )

    #print en_data.encode('hex')
    #print en_data_temp.encode('hex')

    if en_data == en_data_temp:
        sys.stdout.write('%s  True\n' % key[3:].encode('hex'))
        os.exit(1)    #exit



def main():
    p = Pool()

    with open('03fe00', 'r') as f:
        pkt = pickle.load(f)
        en_data = pkt['pkt_wepdata'][0:5]
        pkt_iv = pkt['pkt_iv']

    temp1 = [ chr(x) for x in range(48, 58) ]
    temp2 = [ chr(x) for x in range(97, 103) ]
    temp = temp1 + temp2

    #temp_key = '1234567890'
    #args = {'en_data':en_data, 'key':pkt_iv+temp_key.decode('hex')}
    #print args['key'].encode('hex')
    #p.apply_async(func=baoli, args=(args,))


    for x0 in xrange(len(temp)):
        for x1 in xrange(len(temp)):
            for x2 in xrange(len(temp)):
                for x3 in xrange(len(temp)):
                    for x4 in xrange(len(temp)):
                        for x5 in xrange(len(temp)):
                            for x6 in xrange(len(temp)):
                                for x7 in xrange(len(temp)):
                                    for x8 in xrange(len(temp)):
                                        for x9 in xrange(len(temp)):
                                            temp_key = temp[x0]+temp[x1]+temp[x2]+temp[x3]+temp[x4]+temp[x5]+temp[x6]+temp[x7]+temp[x8]+temp[x9]
                                            print temp_key
                                            args = {'en_data':en_data, 'key':pkt_iv+temp_key.decode('hex')}
                                            p.apply_async(func=baoli, args=(args,))

    p.close()
    p.join()

if __name__ == '__main__':
    print time.ctime()
    main()