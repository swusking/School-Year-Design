#!/usr/bin/env python
#coding:utf-8

import hmac, hashlib
import struct
from operator import xor
from itertools import  imap

'''
参考代码：https://github.com/mitsuhiko/python-wpa/blob/master/wpa.py
pbkdf2_hex：是能够输出的十六进制
pbkdf2_bin：有可能不能输出的字符串
'''

#参数：密钥、盐(明文)、运算次数、输出HMAC长度，hash算法（默认SHA-1，输出20字节）
def pbkdf2_hex(PassPhrase, Salt, Count=1000, dkLen=24, Hashfunc=hashlib.sha1):
    return pbkdf2_bin(PassPhrase,Salt,Count,dkLen,Hashfunc).encode('hex')

def pbkdf2_bin(PassPhrase, Salt, Count=1000, dkLen=24, Hashfunc=hashlib.sha1):
    buffer = []   #存放要输出的结果，块的结果连接起来
    mac = hmac.new(PassPhrase, None, Hashfunc)     #声明一个HMAC对象，将来把Mes填进去

    def hmac_result(mac, salt):
        mac_temp = mac.copy()     #创建一个副本，官网说更加有效的计算
        mac_temp.update(salt)
        return map(ord, mac_temp.digest())      #返回结果

    for i in xrange(1, -(-dkLen // mac.digest_size) + 1):
        #如果这里不转换的换，下面的temp第二次后就会变成ord不是chr，所以会报错
        result = temp = hmac_result(mac, Salt + struct.pack('>I', i))  #大端的无符号整数
        for j in xrange(Count-1):   #因为刚已经执行过一次了
            result = hmac_result(mac, ''.join(map(chr, result)))      #拿上次的结果作为盐值
            temp = imap(xor, temp, result)     #将每次的结果进行异或，迭代器

        buffer.extend(temp) #buffer存放的全是十进制数

    return ''.join(map(chr,buffer))[:dkLen]        #返回结果字符串，必须列表全是字符串才可以

if __name__ == '__main__':
    #验证算法正确
    print "正确答案：",'0c60c80f961f0e71f3a9b524af6012062fe037a6'
    print "计算答案：", pbkdf2_hex('password', 'salt', 1, 20)
    print
    print "正确答案：",'3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'
    print "计算答案：", pbkdf2_hex('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25)
