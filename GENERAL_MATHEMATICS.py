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



def gcd(a,b):
    #if a < b:
    #    a, b = b, a
    while b != 0:
        t = b
        b = a % b
        a = t
    return a


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

#a, b = 26513, 32321
#g, x, y = ext_gcd(a, b)
#print(f"gcd({a}, {b}) = {g}    quotients by the gcd: {x}, {y}")


#Greatest Common Divisor
#-------------------------------------------------------------
#code is lost but it is like below

#Extended GCD
#-------------------------------------------------------------
#a, b = 26513, 32321
#g, x, y = ext_gcd(a, b)
#print(f"gcd({a}, {b}) = {g}    quotients by the gcd: {x}, {y}")


#Modular Arithmetic 1
#-------------------------------------------------------------
#code is lost but it is like a=11%6


#Modular Arithmetic 2
#-------------------------------------------------------------
#here i missed Fermat's little theorem notion AND the fact of existance of pow(a,b,mod)
#so i decided i should write pow(a,b,mod) by myself, why not :D

def mul_mod(a, b, mod):
    return ((a % mod)*(b % mod)) % mod

#all by myself
def pov_mod(a, b, mod):
    #print(f"EVALUATING {a} ^ {b} mod {mod}\n--------------------------")
    a = mul_mod(a, 1, mod)
    return pov_mod1(a, b, mod, a)

def pov_mod1(a, b, mod, binpow):
    #print(f"\na= {a} b= {b} mod= {mod} binpow= {binpow}")
    b2 = b // 2
    k = b % 2
    #print(f"b2= {b2} k= {k}")
    if b == 0: return 1
    if b == 1: return binpow

    next_binpow = mul_mod(binpow ,binpow ,mod)
    #print(f"next_binpow= {next_binpow}")
    next_pov = pov_mod1(a, b2, mod, next_binpow)
    #print(f"next_binpow= {next_binpow} next_pov= {next_pov}")
    if k==1:
        result = mul_mod(binpow, next_pov, mod)
        #print(f"result = mul_mod(binpow, next_pov, mod) = {result}")
    else:
        result = next_pov
        #print(f"result = next_pov = {result}")
    #print(f"result== {result}")
    return result

#print(f"**********\nRESULT   pov_mod(7, 2, 13) r= {pov_mod(7, 2, 13)}\n\n")
#print(f"**********\nRESULT   pov_mod(7, 3, 13) r= {pov_mod(7, 3, 13)}\n\n")
#print(f"**********\nRESULT   pov_mod(7, 4, 13) r= {pov_mod(7, 4, 13)}\n\n")
#print(f"**********\nRESULT   pov_mod(7, 5, 13) r= {pov_mod(7, 5, 13)}\n\n")
#print(f"**********\nRESULT   pov_mod(7, 6, 13) r= {pov_mod(7, 6, 13)}\n\n")

#print("\n")
#print(f"**********   pov_mod(7, 29, 17) r= {pov_mod(7, 29, 17)}")
#print(f"**********   pov_mod(3, 17, 17) r= {pov_mod(3, 17, 17)}")
#print(f"**********   pov_mod(5, 17, 17) r= {pov_mod(5, 17, 17)}")
#print(f"**********   pov_mod(7, 16, 17) r= {pov_mod(7, 16, 17)}")
#print(f"**********   pov_mod(273246787654, 65536, 65537) r= {pov_mod(273246787654, 65536, 65537)}")


#Modular Inverting
#-------------------------------------------------------------
#What is the inverse element: 3 * d ≡ 1 mod 13?
#print(f"**********   pov_mod(3, 11, 13) r= {pov_mod(3, 11, 13)}")

