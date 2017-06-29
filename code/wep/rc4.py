#/usr/bin/env python
#coding:utf-8


#输入传入的数据和密钥，传入的参数都为字符串
def rc4_encode(data, key):
    statu_v = range(256)  #状态向量
    temp_v = [ ord(key[x % len(key)]) for x in range(256)]  #初始向量
    en_data = ''  #加密的结果

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
        en_data += chr( ord(data[x]) ^ statu_v[t] )

    return en_data

def main():
    data = '\xaa\xaa\x03\x00\x00'             #获得需要加密的数据
    key = '\x7f\x93\xd4\x12\x34\x56\x78\x90'  #获得密钥 IV+KEY

    en_data = rc4_encode(data=data, key=key)
    print en_data.encode('hex')

if __name__ == '__main__':
    main()
