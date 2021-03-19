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

#RSA Starter 1
#---------------------------------------------------------------------------------
#print(pow(101,17,22663))

#RSA Starter 2
#---------------------------------------------------------------------------------
#message=12
#rsa: message**e mod (N=p*q) where p,q primes, most common e is 0x10001 or 65537
#RSA public key is (N,e)
#print(pow(message,65537,17*23))

#RSA Starter 3
#---------------------------------------------------------------------------------
#Euler’s Totient - Функція Ейлера
#phi(N) = count of integers less than N that are coprime to N
#if M coprime N - phi(N*M)=phi(N)*phi(N)

"""
def euler_function(n):
    ret = 1
    for i in range(2, math.floor(n**0.5)):
        p = 1
        while not n % i:
            p *= i
            n /= i
        p /= i
        if p >= 1:
            ret = ret * p * (i - 1)
    n -= 1
    return n * ret if n else ret
"""

#p = 857504083339712752489993810777
#q = 1029224947942998075080348647219
#t=euler_function(17)
#print((p-1)*(q-1))

#RSA Starter 4
#---------------------------------------------------------------------------------
def ext_gcd(a, b):
    # Base Case
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = ext_gcd(b % a, a)
    # Update x and y using results of recursive
    # call
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

#RSA public key is (N,e) N=p*q where p,q primes
#RSA private key (d) is modular multiplicative inverse of the exponent e modulo the totient of N.

p = 857504083339712752489993810777
q = 1029224947942998075080348647219
e = 65537
N= p * q
#totient of N t(N)= (p-1)*(q-1)
t=(p-1)*(q-1)
print(f"toitent of N= {t}")
#modular multiplicative inverse of the A is X such that A*X≡1 mod m (A*X mod m == 1)
#modular multiplicative inverse of the e is X such that e*X≡1 mod t(N) (e*X mod t(N) == 1)
#ext_gcd(a, b) -> gcd, x,y
#ext_gcd(e, t(N)) -> gcd(e,t(N)), x,y
#a*x+b*y=gcd(a,b), a and x are modular multiplicative inverse mod b
#e*x+t(N)*y=gcd(e,t(N)), e and x are modular multiplicative inverse mod t(N)

gcd,x,y = ext_gcd(e, t)
#print(f"gcd({e},{t}) = {gcd}")
d=x
#print(f"modular multiplicative inverse of the e mod t(N)= {d}")

#RSA Starter 5
#---------------------------------------------------------------------------------
#print(f"N= {N}")
#m=555
#me=pow(m,e,N)
#print(f"encrypting {m} -> m^e mod N ={me}")
#me=77578995801157823671636298847186723593814843845525223303932
#m2=pow(me,d,N)
#print(f"decrypting {me} -> me^d mod N ={m2}")

#RSA Starter 6
#---------------------------------------------------------------------------------
N = 15216583654836731327639981224133918855895948374072384050848479908982286890731769486609085918857664046075375253168955058743185664390273058074450390236774324903305663479046566232967297765731625328029814055635316002591227570271271445226094919864475407884459980489638001092788574811554149774028950310695112688723853763743238753349782508121985338746755237819373178699343135091783992299561827389745132880022259873387524273298850340648779897909381979714026837172003953221052431217940632552930880000919436507245150726543040714721553361063311954285289857582079880295199632757829525723874753306371990452491305564061051059885803
d = 11175901210643014262548222473449533091378848269490518850474399681690547281665059317155831692300453197335735728459259392366823302405685389586883670043744683993709123180805154631088513521456979317628012721881537154107239389466063136007337120599915456659758559300673444689263854921332185562706707573660658164991098457874495054854491474065039621922972671588299315846306069845169959451250821044417886630346229021305410340100401530146135418806544340908355106582089082980533651095594192031411679866134256418292249592135441145384466261279428795408721990564658703903787956958168449841491667690491585550160457893350536334242689
flag = "crypto{Immut4ble_m3ssag1ng}"
mh=hashlib.sha256(flag.encode())
mh_int=int.from_bytes(mh.digest(),byteorder="big")
print(f"sha256= {mh_int}")
me=pow(mh_int,d,N)
print(f"me= {hex(me)[2:]}")


