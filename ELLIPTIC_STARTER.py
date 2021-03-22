import telnetlib
import json
import base64
import binascii
import Crypto.Util.number
from pwn import *
import codecs
import random
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse
from math import gcd

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os


#STARTER - Point Negation
#-------------------------------------------------------------------------------------
#Y^2 = X^3 + 497 X + 1768    p: 9739
a=497
b=1768
p = 9739
P = (8045,6936)
#P(8045,6936), find the point Q(x,y) such that P + Q = O.

"""
#Q = (p-P[0],p-P[1])
Q = (P[0],p-P[1])
#print(Q)

P = (8045,6936)
X, Y = P
print(f"for {(X, Y)} - Y^2({pow(Y,2,p)}) = X^3 + {a} X + {b} ({(pow(X,3,p)+ a*X + b) % p}) ")
Q = (P[0],p-P[1])
X, Y = Q
print(f"for {(X, Y)} - Y^2({pow(Y,2,p)}) = X^3 + {a} X + {b} ({(pow(X,3,p)+ a*X + b) % p}) ")

X, Y = 0, 0
print(f"for {(X, Y)} - Y^2({pow(Y,2,p)}) = X^3 + {a} X + {b} ({(pow(X,3,p)+ a*X + b) % p}) ")
"""

#STARTER - Point Addition
#-------------------------------------------------------------------------------------
# a/b mod p == a * inverse(b,p) mod p
a = 497
b = 1768
p = 9739
O=(0, 0)

def div_mod(a,b):
    return (a * inverse(b,p)) % p

def isO(P):
    if P==O: return True
    return False

def ell_add(P,Q):
    if isO(P): return Q
    if isO(Q): return P
    X1,Y1 = P[0],P[1]
    X2,Y2 = Q[0],Q[1]
    if X1==X2 and Y1==(p-Y2): return O
    if X1==X2 and Y1==Y2:
        L = div_mod((3*pow(X1,2,p) + a) % p, (Y1 * 2) % p)
    else:
        L = div_mod((Y2-Y1+p) % p, (X2-X1+p) % p)
    X3 = (pow(L,2,p) - X1 - X2 + p * 2) % p
    Y3 = ((L * ((X1 - X3 + p) % p)) % p - Y1 + p) % p
    return (X3,Y3)

def sc_el_mul(Q,n):
    R=O
    while n > 0:
        if n % 2 == 1: R = ell_add(R,Q)
        Q = ell_add(Q,Q)
        n=n//2
    return R

"""
X = (5274, 2841)
Y = (8669, 740)
print(f" X+Y= {ell_add(X,Y)}")
print(f" X+X= {ell_add(X,X)}")

P = (493, 5564)
Q = (1539, 4742)
R = (4403,5202)
S = ell_add(R,ell_add(Q,ell_add(P,P)))
print(f"S(x,y) = P + P + Q + R = {S}")
"""

#X, Y = S
#print(f"for {(X, Y)} - Y^2({pow(Y,2,p)}) = X^3 + {a} X + {b} ({(pow(X,3,p)+ a*X + b) % p}) ")

#STARTER - Scalar Multiplication
#-------------------------------------------------------------------------------------

#X = (5323, 5438)
#print(f" 1337 X = {sc_el_mul(X,1337)}")
#P = (2339, 2213)
#print(f" 7863 P = {sc_el_mul(P,7863)}")

#STARTER - Curves and Logs
#-------------------------------------------------------------------------------------
#Alice and Bob agree on a curve E, a prime p and a generator point G
G = (1804,5368)
"""
#Alice generates a secret random integer nA and calculates QA = nA * G
QA = (815, 3190)
#Bob generates a secret random integer nB and calculates QB = nB * G
nB = 1829
QB = sc_el_mul(G,nB)
#Alice sends Bob QA, and Bob sends Alice QB. Due to the hardness of ECDLP, an onlooker Eve is unable to calculate nA/B in reasonable time.
#Alice then calculates nAQB, and Bob calculates nBQA.
#Due to the associativity of scalar multiplication, S = nAQB = nBQA.
#Alice and Bob can use S as their shared secret.
S = sc_el_mul(QA,nB)
print(f"S= {S}")
S = str(S[0])
print(f"S= {S}")
mh=hashlib.sha1(S.encode())
S=mh.hexdigest()
print(f"S= {S}")

"""
#STARTER - Scalar Multiplication
#-------------------------------------------------------------------------------------
def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))


def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')

#i understand that "For these challenges, we have used a prime p ≡ 3 mod 4, which will help you find y from y2"
#gives me easier algorythm for sqrt with such primes but i opted to find general solution for future uses:
#https://codereview.stackexchange.com/questions/43210/tonelli-shanks-algorithm-implementation-of-prime-modular-square-root

def legendre_symbol(a, p):
    ls = pow(a, (p - 1)//2, p)
    if ls == p - 1:
        return -1
    return ls

def prime_mod_sqrt(a, p):
    """
    Square root modulo prime number
    Solve the equation
        x^2 = a mod p
    and return list of x solution
    http://en.wikipedia.org/wiki/Tonelli-Shanks_algorithm
    """
    a %= p

    # Simple case
    if a == 0:
        return [0]
    if p == 2:
        return [a]

    # Check solution existence on odd prime
    if legendre_symbol(a, p) != 1:
        return []

    # Simple case
    if p % 4 == 3:
        x = pow(a, (p + 1)//4, p)
        return [x, p-x]

    # Factor p-1 on the form q * 2^s (with Q odd)
    q, s = p - 1, 0
    while q % 2 == 0:
        s += 1
        q //= 2

    # Select a z which is a quadratic non resudue modulo p
    z = 1
    while legendre_symbol(z, p) != -1:
        z += 1
    c = pow(z, q, p)

    # Search for a solution
    x = pow(a, (q + 1)//2, p)
    t = pow(a, q, p)
    m = s
    while t != 1:
        # Find the lowest i such that t^(2^i) = 1
        i, e = 0, 2
        for i in xrange(1, m):
            if pow(t, e, p) == 1:
                break
            e *= 2

        # Update next value to iterate
        b = pow(c, 2**(m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i

    return [x, p-x]


#alice QA = (4726, ?)
QAx = 4726

#Y^2 = X^3 + 497 X + 1768    p: 9739
Y2 = (pow(QAx,3,p)+ a * QAx + b) % p
print(f"Y^2= {Y2}")
Y=prime_mod_sqrt(Y2,p)
print(f"Y= {Y} Y2= {(Y[0]*Y[0])%p} , {(Y[1]*Y[1])%p}")

QA = (QAx, Y[0])
nB = 6534
S = sc_el_mul(QA,nB)
print(f"S= {S}")
data={'iv': 'cd9da9f1c60925922377ea952afc212c', 'encrypted_flag': 'febcbe3a3414a730b125931dccf912d2239f3e969c4334d95ed0ec86f6449ad8'}
print(decrypt_flag(S[0], data["iv"], data["encrypted_flag"]))

