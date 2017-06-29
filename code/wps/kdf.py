#!/usr/bin/env python
#coding:utf-8

import hashlib, hmac
import struct

def kdf(key, string, bits):
    result = ''
    mac = hmac.new(key, None, hashlib.sha256)
    
    def get_mac(mac, string):
        mac_temp = mac.copy()
        mac_temp.update(string)
        return mac_temp.digest()
    
    for i in range(1, -(-bits // (mac.digest_size*8)) + 1):  #mac.digest_size = 32*8
        result += get_mac(mac, struct.pack('>I', i) + string + struct.pack('>I', bits)) #大端32位无符号整数
    
    return result[:80]
    
    
def main():
    
    KDK = '540d9c38bfacf64dabffdfee651e42324f62924e0dfd8872f314070b4666e998'.decode('hex')
    string = 'Wi-Fi Easy and Secure Key Derivation'
    bits = 640

    print kdf(KDK, string, bits).encode('hex')

if __name__ == '__main__':
    main()