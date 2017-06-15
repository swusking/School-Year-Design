#!/usr/bin/env python
#coding:utf-8

import pbkdf2, prf512
import hmac, hashlib

def get_mic(data, ptk):
    mic_key = ptk[0:16]
    # 注意参数，都是字符串，不是十六进制
    mic = hmac.new(mic_key, data, hashlib.sha1).hexdigest()
    return mic

def main():
    passPhrase = "LINUXZSJ"
    ssid = "TP-LINK_4F6C90"
    A = "Pairwise key expansion\0"
    APmac = "20dce64f6c90".decode('hex')
    Clientmac = "e0b9a51fe794".decode('hex')
    ANonce = "3320ced2535ed697d52c272aeea799d4d188a4603142f37a240f8064d7cdf588".decode('hex')
    SNonce = "b4455d0bc446645c5957434f653ad0bfa59f6be1a265fbf33b7d547b1b484534".decode('hex')
    B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)

    psk = pbkdf2.pbkdf2_hex(passPhrase, ssid, 4096, 256)[:64]  #只取64字节数据
    pmk = psk.decode('hex')          #转换为字符串，变成32字节数据，也就是256bits
    ptk = prf512.prf512(pmk, A, B)

    #从wireshark取数据时，要把MIC置0，16个字节
    data = '020300970213ca001000000000000000023320ced2535ed697d52c272aeea799d4d188a4603142f37a240f8064d7cdf58800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000384bcaf58aee04b67d65c62b951ece909c5c5ae86e455ecfd5059ac633ad1e69fc480863014155b620e0b5350297306f3c76245cb1ec6f306a'
    # d88518e6e4076d06c20879a9366831c9
    print get_mic(data.decode('hex'), ptk)



if __name__ == '__main__':
    main()