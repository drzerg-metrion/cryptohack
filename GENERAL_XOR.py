#!/usr/bin/env python3
# cryptohack

import telnetlib
import json
import base64
import binascii
import Crypto.Util.number
from pwn import *
import codecs
import random
from Crypto.PublicKey import RSA

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

#Encoding Challenge
#-------------------------------------------------------------
#data="label"
#result=""
#for i in data:
#    result += chr(ord(i) ^ 13)
#print(result)


#XOR Properties
#-------------------------------------------------------------
#KEY1 = bytes.fromhex("a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313")
#KEY2_KEY1 = bytes.fromhex("37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e")
#KEY2_KEY3 = bytes.fromhex("c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1")
#FLAG_KEY1_KEY3_KEY2 = bytes.fromhex("04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf")

#result=xor(FLAG_KEY1_KEY3_KEY2,xor(KEY2_KEY3,KEY1))
#print(result.decode())

#0 0 = 0
#1 0 = 1
#0 1 = 1
#1 1 = 0


#Favourite byte
#-------------------------------------------------------------
#data = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
#KEY1 = bytes.fromhex(data)
#for i in range(255):
#    TESTKEY = bytes([i]) * len(data)
#    #print(TESTKEY)
#    result=xor(TESTKEY,KEY1).decode()
#    print(f"result[:6]={result[:6]}  result={result}")
#    if result[:6] == "crypto":
#        print(f"\n\n\n!!!!!!!!!!\n result={result} \n111111111\n\n\n")
#        break


#You either know, XOR you don't
#-------------------------------------------------------------
data = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"
template="crypto{"
length=7

KEY1 = bytes.fromhex(data)
print(f"KEY1= {KEY1}")
KEY0 = "crypto{".encode()
print(f"KEY0= {KEY0}")
KEY2 = xor(KEY0[:length],KEY1[:length])
print(f"KEY2= {KEY2}")
KEY4 = xor(KEY1,KEY2)
print(f"KEY4= {KEY4}")
result = KEY4.decode()
print(result)
print(xor(KEY1,"myXORkey".encode()))


#Lemur XOR
#-------------------------------------------------------------
#online photoshop
