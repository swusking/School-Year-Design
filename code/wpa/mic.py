#!/usr/bin/env python
#coding:utf-8

import pbkdf2, prf512
import hmac

def get_mic(data, ptk):
    mic_key = ptk[0:16]
    # 注意参数，都是字符串，不是十六进制
    mic = hmac.new(mic_key, data).hexdigest()
    return mic

def main():
    passPhrase = "LINUXZSJ"
    ssid = "TP-LINK_4F6C90"
    A = "Pairwise key expansion\0"
    APmac = "20dce64f6c90".decode('hex')
    Clientmac = "e0b9a51fe794".decode('hex')
    ANonce = "3320ced2535ed697d52c272aeea799d4d188a4603142f37a240f8064d7cdf58f".decode('hex')
    SNonce = "93b0f1cd466efd5f6eb146ffbad9c9c86a74a961539dd3ef3b47f50da5298266".decode('hex')
    B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)

    psk = pbkdf2.pbkdf2_hex(passPhrase, ssid, 4096, 256)[:64]  #只取64字节数据
    pmk = psk.decode('hex')          #转换为字符串，变成32字节数据，也就是256bits
    ptk = prf512.prf512(pmk, A, B)

    #从wireshark取数据时，要把MIC置0，16个字节
    data = '02030077fe01c9002000000000000000023320ced2535ed697d52c272aeea799d4d188a4603142f37a240f8064d7cdf58f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018dd160050f20101000050f20201000050f20201000050f202'
    # ce52ff9185830f6bf2f50e1d59d564b4
    print get_mic(data.decode('hex'), ptk)

if __name__ == '__main__':
    main()

