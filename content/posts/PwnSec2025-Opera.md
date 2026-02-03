
---
title: "PwnSec2025-Opera"
date: 2025-05-03
draft: false
---

# Challenge :

```python
#!/usr/bin/env python3
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from pwn import xor
import os, sys, random

FLAG = os.getenv("FLAG", "flag{b3n34th_th3_m45k_pwnsecsocool}").encode()
    
class LCG:
    def __init__(self, m=1<<64):
        self.m = m
        self.a = random.getrandbits(64)|1
        self.c = random.getrandbits(64)|1
        self.x = random.getrandbits(64)
    def next(self): 
        self.x=(self.a*self.x+self.c)%self.m
        return self.x
    def stream(self, n):
        out=b""
        while len(out)<n: out+=self.next().to_bytes(8,"big")
        return out[:n]

class RSA:
    def __init__(self, bits=512, e=65537):
        self.e=e
        self.p=getPrime(bits//2)
        self.q=getPrime(bits//2)
        self.n=self.p*self.q
    def enc(self, m_bytes, mod):
        k=(mod.bit_length()+7)//8
        m=bytes_to_long(m_bytes)
        assert m<mod
        return long_to_bytes(pow(m,self.e,mod),k)

def main():
    random.seed(os.urandom(16))
    rsa, lcg = RSA(bits=512), LCG()
    Cflag = rsa.enc(FLAG, rsa.n)
    enc_flag = xor(Cflag, lcg.stream(len(Cflag)))

    menu="1) get encrypted flag\n2) encrypt your input\n3) exit\n> "
    while True:
        try:
            c=input(menu).strip()
            if c=="1":
                print(enc_flag.hex())
                print(rsa.n)  
            elif c=="2":
                s=input("> ")
                m=s.encode()
                if bytes_to_long(m)>=rsa.p: 
                    print("too long")
                    continue
                C=rsa.enc(m, rsa.p)
                print(xor(C, lcg.stream(len(C))).hex())  
            elif c=="3":
                print("bye")
                return
            else: 
                print("don't waste our time")
                return
        except:
            print("error")
            sys.exit(0)

if __name__=="__main__": main()% 
```


# High level :

The challenge is consisted of two layers of "pseudo-random generator LCG" and an RSA scheme, and the two layers have very clear vulnerabilities.

# Vulnerabilities :

The first is that the server doesn't check for empty string, which we will take advantage of.
And the second is that the server encrypt OUR message in RSA using the prime $p$, which is not secure at all, it is supposed to use $N$ as the modulus.

```python
s=input("> ") # anything can go here (Vulnerability 1)
m=s.encode()
if bytes_to_long(m)>=rsa.p: 
	print("too long")
	continue
C=rsa.enc(m, rsa.p) # (Vulnerability 2)
print(xor(C, lcg.stream(len(C))).hex())  
```

# The Attack :

1. We first get the encrypted flag and also the modulus $N$.
2. We encrypt the empty message "" (just once I did twice in order to confirm my way is correct).
3. And then we encrypt any message, this step is involved in the RSA layer.

### The math :

If s is an empty string then m = 0, thus we get the stream itself :

$$
output = C \oplus stream = Enc(m) \oplus stream = 0 \oplus stream = stream
$$

Now we just need to recover the LCG parameters $(a, c)$, and now recovering the Enc_flag is easy because we can reverse the LCG and go back to the previous states $x_i$, thus recovering $Enc(flag)$
which is :

$$
EncFLAG
 = Enc(FLAG) = FLAG^e \pmod{N}
$$

Now we need to break the RSA layer, and to do so, we need some math :
We have the encrypted arbitrary text which I have chosen to be "A" so :

$$
\text{Let } A \text{ be the integer representing "A".} \\
A = \mathrm{ord}("A") \\
$$

$$
a \equiv A^e \pmod{p} \\
$$

$$
b \equiv A^e \pmod{N}
$$

This means:

$$
a - b \equiv 0 \pmod{p} \iff\ p \mid (a-b)
$$

Since $p$ is divisor of both $(a-b)$ and $N$, we can factor $N$ using GCD, so $p = gcd(N, a-b)$.

# The Script :

```python
from chall import *

# ================ first REQ (encrypt flag) ===========================
N = 4916080727098179914441241519095552553856565700728450075108170059002990957939138896547105292967739166027945377243402934097595656728822101653101831279139531
enc_flag = bytes.fromhex("7522d4be9b90773ef12ac08c421cc5f530fca2fb770627b78b4bf6eb65cafd42160110520ec65a7f47710cf7656915e4ee1e13d2ed38d83d7207504acb66a968")
flaglen = len(enc_flag)

# ================ second REQ (encrypt empty string) ===========================
second_res = bytes.fromhex("d52700e2d5afba119e8b1ef7a43f3b80ce64e020c33c29add39fe92d6aa2edd4")

# ================ third REQ (encrypt empty string) ===========================
third_res = bytes.fromhex("0b60eac0d73cdb29385180dd650321c8bdb94ae5bdf9c5855f993575d5929c5c")

# ================ forth REQ (encrypt "A") ===========================

A_enc = bytes.fromhex("58f94332a306f99f84e95766814dd46f0931a2bcd3251f6bcf22ce3268fb3400")

# ================ SOLVE AJMI ===========================
def recover_lcg_states(stream):
    m = 1 << 64
    xs = [int.from_bytes(stream[i:i+8], "big") for i in range(0, len(stream), 8)]
    x1, x2, x3 = xs[0], xs[1], xs[2]
    d1 = (x2 - x1) % m
    d2 = (x3 - x2) % m
    a = (d2 * pow(d1, -1, m)) % m
    c = (x2 - a*x1) % m
    return a, c, m

a, c, m = recover_lcg_states(second_res)
a, c, m = recover_lcg_states(third_res)
# the first output is comfirmed to identical to the second

ainv = pow(a, -1, m)
def prev(x):
    return (ainv * (x - c)) % m

def next(x): 
    x=(a*x+c)%m
    return x

xs3 = [int.from_bytes(third_res[i:i+8], "big") for i in range(0, len(third_res), 8)]
xs2 = [int.from_bytes(second_res[i:i+8], "big") for i in range(0, len(second_res), 8)]

print("doing good ? ", xs2[-1] == prev(xs3[0]))

xs1 = [prev(x) for x in xs2]

def complete_stream_prev(xs, l):
    need = (l - len(xs)) // len(xs[0].to_bytes(8,"big"))
    for _ in range(need):
        xs.insert(0, prev(xs[0]))
    
def complete_stream_next(xs, l):
    need = (l - len(xs)) // len(xs[0].to_bytes(8,"big"))
    for _ in range(need):
        xs.append(next(xs[-1]))
    
complete_stream_prev(xs1, len(enc_flag))

def xs_to_bytes(xs, n):
    out=b""
    i=0
    while len(out)<n:
        out+=xs[i].to_bytes(8,"big")
        i = i+1
    return out

C0 = (xor(xs_to_bytes(xs1, flaglen), enc_flag))
print(C0.hex())

from Crypto.Util.number import *

xs4 = [next(xs3[-1])]
complete_stream_next(xs4, len(A_enc))
A = (xor(xs_to_bytes(xs4[-len(A_enc):], len(A_enc)), A_enc))
print(A)
s="A"
m=s.encode()
e = 0x10001
B = pow(bytes_to_long(m), e, N)
import math
p = (math.gcd(B-bytes_to_long(A), N))

print(p)
print("are we good ? ", N%p==0 and p != 1)

q=N//p
# ========== Decrypt FLAG ============

print(long_to_bytes(pow(bytes_to_long(C0), pow(e, -1, (p-1)*(q-1)), N)))

# ========== OUTPUT ============
# doing good ?  True
# 2c1a38c828a55d5f9e630a8f940a1385e15aec1252ac3fca89c1ad84a7372906e06ee4a7a3ca46062f6c7038d2df5a5c7d647aa2fe0015685c0eac70430144a4
# b'O{\x04\x9c?\xf1.^\xf4g\xf6\xde\x08\xf7\xde\xff\x18\xb4\x0c^\xd6\x9f\xa7\xb6\xaa\xb8/\x1aYnud'
# 61737447455151085190911017044968419618689478567149066920180466069341485265367
# are we good ?  True
# b'flag{abc87ec0bc4741ab}'%  
```
