#!/usr/bin/env python
#coding:utf-8

import pbkdf2
import hmac, hashlib

def prf512(pmk, A, B):
    ptk1 = hmac.new(pmk, A + B + chr(0), hashlib.sha1).digest()        #20字节
    ptk2 = hmac.new(pmk, A + B + chr(1), hashlib.sha1).digest()        #20字节
    ptk3 = hmac.new(pmk, A + B + chr(2), hashlib.sha1).digest()        #20字节
    ptk4 = hmac.new(pmk, A + B + chr(3), hashlib.sha1).digest()[0:4]   #4字节
    return ptk1 + ptk2 + ptk3 + ptk4       #64字节=512bits

if __name__ == '__main__':
    pass