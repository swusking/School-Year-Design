#!/usr/bin/env python
#coding:utf-8

import pbkdf2, prf512
import hmac, hashlib

def get_mic(Passphrase, SSID, AP_MAC, STA_MAC, ANonce, SNonce, DATA):
    A = "Pairwise key expansion\0"
    B = min(AP_MAC.decode('hex'), STA_MAC.decode('hex')) + max(AP_MAC.decode('hex'), STA_MAC.decode('hex')) + min(ANonce.decode('hex'), SNonce.decode('hex')) + max(ANonce.decode('hex'), SNonce.decode('hex'))
    
    psk = pbkdf2.pbkdf2_hex(Passphrase, SSID, 4096, 256)[:64]  #只取64字节数据
    pmk = psk.decode('hex')          #转换为字符串，变成32字节数据，也就是256bits
    ptk = prf512.prf512(pmk, A, B)    
    
    mic_key = ptk[0:16]
    # 注意参数，都是字符串，不是十六进制
    mic = hmac.new(mic_key, DATA.decode('hex'), hashlib.sha1).hexdigest()[0:32]   #只取前32位
    return mic

def main():
    Passphrase = "LINUXZSJ"
    SSID = "TP-LINK_4F6C90"
    APmac = "20dce64f6c90"
    Clientmac = "e0b9a51fe794"
    ANonce = "3320ced2535ed697d52c272aeea799d4d188a4603142f37a240f8064d7cdf58f"
    SNonce = "93b0f1cd466efd5f6eb146ffbad9c9c86a74a961539dd3ef3b47f50da5298266"
    
    #从wireshark取数据时，要把MIC置0，16个字节
    data = '02030077fe01c9002000000000000000023320ced2535ed697d52c272aeea799d4d188a4603142f37a240f8064d7cdf58f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018dd160050f20101000050f20201000050f20201000050f202'

    # 637056462428636a75835b7778e0740df9f13c46
    print get_mic(Passphrase, SSID, APmac, Clientmac, ANonce, SNonce, data)

if __name__ == '__main__':
    main()


    
    