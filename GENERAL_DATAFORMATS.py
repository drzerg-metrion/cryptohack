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

#Privacy-Enhanced Mail?
#-------------------------------------------------------------
#f = open('key.pem','r')
#key = RSA.import_key(f.read())
#print(key.exportKey)

#CERTainly not
#-------------------------------------------------------------
#f = open('key.der','rb')
#key = RSA.import_key(f.read())
#print(key.exportKey)


#Transparency
#-------------------------------------------------------------
#NOT DONE
