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

#ASCII
#-------------------------------------------------------------

#data = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
#result=""
#for i in data:
#    result+=chr(i)
#print(result)

#Hex
#-------------------------------------------------------------
#data = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"
#result = ""
#i = 0
#while i < len(data):
#    result += chr(int(data[i:i+2], 16))
#    i+=2
#print(result)

#Base64
#-------------------------------------------------------------
#data = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"
#result = b''
#print(f'result at start= {result}')
#i = 0
#while i < len(data):
#    n=int(data[i:i+2], 16)
#    c=chr(n)
#    e=c.encode()
#    b=n.to_bytes(1,byteorder='big')
#    print(f"byte[{int(i/2)}]= {n} char={c} encode={e} b={b}")
#    result += b
#    i+=2

#hex = binascii.unhexlify(data)
#print(f"hex= {hex}")
#print(f"result= {result}")

#flag = base64.b64encode(result)
#res = flag.decode("ascii")
#print(res)

#Bytes and Big Integers
#-------------------------------------------------------------
#data="11515195063862318899931685488813747395775516287289682636499965282714637259206269"
#t=Crypto.Util.number.long_to_bytes(data)
#print(f"t= {t}")

#Encoding Challenge
#-------------------------------------------------------------

r = remote('socket.cryptohack.org', 13377, level = 'debug')
#r = remote('socket.cryptohack.org', 13377)

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

def hex_decode(data):
    result = ""
    i = 0
    while i < len(data):
       result += chr(int(data[i:i+2], 16))
       i+=2
    return result



for i in range(101):
    print(f" ****** iteration: {i}")
    received = json_recv()
    print(f" ****** Received: {received}")

    if "flag" in received.keys():
        print(f"FLAG: [{received['flag']}]   !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    elif "error" in received.keys():
        print("DECODING ERROR - stop")
        break
    else:
        decoded=""
        encoding = received["type"]
        challenge_words = received["encoded"]
        if encoding == "base64":
            decoded = base64.b64decode(challenge_words.encode()).decode()  # wow so encode
        elif encoding == "hex":
            decoded = hex_decode(challenge_words)
        elif encoding == "rot13":
            decoded = codecs.decode(challenge_words, 'rot_13')
        elif encoding == "bigint":
            decoded = hex_decode(challenge_words[2:])
            #print(f"bigint decoded_hex = {decoded}")
            #decoded = Crypto.Util.number.long_to_bytes(decoded)
        elif encoding == "utf-8":
            for i in challenge_words:
                decoded+=chr(i)

        to_send = { "decoded": decoded }
        json_send(to_send)

print("THE END")
r.close()







