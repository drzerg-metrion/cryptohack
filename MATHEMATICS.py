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


def neg_mod(a, mod):return mod - (a % mod)

def mul_mod(a, b, mod):
    return ((a % mod)*(b % mod)) % mod

def pow_mod(a, b, mod):
    #print(f"EVALUATING {a} ^ {b} mod {mod}\n--------------------------")
    a = mul_mod(a, 1, mod)
    return pow_mod1(a, b, mod, a)

def pow_mod1(a, b, mod, binpow):
    #print(f"\na= {a} b= {b} mod= {mod} binpow= {binpow}")
    b2 = b // 2
    k = b % 2
    #print(f"b2= {b2} k= {k}")
    if b == 0: return 1
    if b == 1: return binpow

    next_binpow = mul_mod(binpow ,binpow ,mod)
    #print(f"next_binpow= {next_binpow}")
    next_pow = pow_mod1(a, b2, mod, next_binpow)
    #print(f"next_binpow= {next_binpow} next_pow= {next_pow}")
    if k==1:
        result = mul_mod(binpow, next_pow, mod)
        #print(f"result = mul_mod(binpow, next_pow, mod) = {result}")
    else:
        result = next_pow
        #print(f"result = next_pow = {result}")
    #print(f"result== {result}")
    return result

#MODULAR MATH - Quadratic Residues
#-------------------------------------------------------------

def isqr_mod(a, mod):
    result = False
    for i in range(mod):
        #print(f"i= {i} a= {a}")
        #print(f"i**2 mod({mod})= {mul_mod(i,i,mod)}   (-i)**2 mod({mod})= {mul_mod(neg_mod(i, mod),neg_mod(i, mod),mod)}")
        if mul_mod(i,i,mod) == a or mul_mod(neg_mod(i, mod),neg_mod(i, mod),mod) == a:
            #print(f"sqroot(a) mod {mod}= {i}")
            result = True
    return result

#p = 29
#ints = [14, 6, 11]
#for i in ints:
#    print(f"is {i} mod {p} quadratic residue? {isqr_mod(i, p)} ")

#Legendre's Symbol - modulo must be prime
def leg_mod(a, mod):
    return pow_mod(a,(mod-1)//2 ,mod)

def isqr_mod2(a, mod):
    if leg_mod(a, mod) == mod-1:
        return False
    return True

#LATTICES - Vectors
#-------------------------------------------------------------

def add_vec(a,b,sign=1):
    r=[]
    for i in range(len(a)):
        r+=[a[i]+b[i]*sign]
    return r

def mulsk_vec(a,b):
    r=[]
    #print(f"len(a)={len(a)}")
    for i in range(len(a)):
        #print(f"i={i}")
        r+=[a[i]*b]
    return r

def dot_vec(a,b):
    r=0
    for i in range(len(a)):
        r+=a[i]*b[i]
    return r

#def add_vec(a,b):
#def mulsk_vec(a,b):
#def dot_vec(a,b):

#v = [2,6,3]
#w = [1,0,0]
#u = [7,7,2]

#3*(2*v - w) ∙ 2*u
#print(dot_vec(mulsk_vec(add_vec(mulsk_vec(v,2),w,-1),3),mulsk_vec(u,2)))
