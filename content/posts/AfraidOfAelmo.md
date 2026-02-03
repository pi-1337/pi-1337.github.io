---
title: "AfraidOfAelmo"
date: 2026-02-03
draft: false
---

# Zero-Knowledge Challenge Write-up

The the challenge is a Zero Knowledge Scheme, where the server tries to prove to the player their knowledge of a witness $w$ (which is the flag), without revealing the *witness*.

# The Script:
```python
FLAG  = os.getenv("FLAG", "Lorem ipsum dolor sit amet consectetur adipiscing elit. Pretium tellus duis convallis tempus leo eu aenean. Iaculis massa nisl malesuada lacinia integer nunc posuere. Conubia nostra inceptos himenaeos orci varius natoque penatibus. Nulla molestie mattis scelerisque maximus eget fermentum odio. Blandit quis suspendisse aliquet nisi sodales consequat magna. Ligula congue sollicitudin erat viverra ac tincidunt nam. Velit aliquam imperdiet mollis nullam volutpat porttitor ullamcorper. Dui felis venenatis ultrices proin libero feugiat tristique. Cubilia curae hac habitasse platea dictumst lorem ipsum. Sem placerat in id cursus mi pretium tellus. Fringilla lacus nec metus bibendum egestas iaculis massa. Taciti sociosqu ad litora torquent per conubia nostra. Ridiculus mus donec rhoncus eros lobortis nulla molestie. Mauris pharetra vestibulum fusce dictum risus blandit quis. Finibus facilisis dapibus etiam interdum tortor ligula congue. Justo lectus commodo augue arcu dignissim velit aliquam. Primis vulputate ornare sagittis vehicula praesent dui felis. Senectus netus suscipit auctor curabitur facilisi cubilia curae. Quisque faucibus ex sapien vitae pellentesque sem placerat. flag{dGhpbmtfeW91J3JlX3NtYXJ0X2h1aD8=}").encode()


class ZKP:
    def __init__(self):
        self.p = getPrime(256)
        self.q = getPrime(256) 
        self.g = 2
        self.w = b2l(FLAG) 
        self.y = pow(self.g, self.w, self.p)
    def prover(self):
            r = randbelow(1 << 200)
            a = pow(self.g, r, self.p)
            e = randbelow(1 << 256)
            z = (r + self.w * e) % self.q
            proof = {"a": a, "e": e, "z": z}
            return proof
    def __str__(self):
        return f"ZKP PUBLIC PARAMETERS:\np = {self.p}\nq = {self.q}\ng = {self.g}\ny = {self.y}"

user = ZKP()

menu = """
[1] Prover
[2] Exit
"""
def main():
    ctr = 0
    print(user)
    print(f'hint: {b2l(FLAG).bit_length()}...you\'re welcome :)')

    while True:
        print(menu)
        choice = input("Select an option > ")
        if choice == '1':
            if ctr >= 6:
                print("You have reached the maximum number of proofs.")
                continue
            
            print("Prover selected.")
            print(f'Here is your proof: {user.prover()}')
            ctr += 1

        elif choice == '2':
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
```

This is a Zero-knowledge Scheme, the $witness$ is $w$ and proof is consisted of $(a, e, z)$, where a $a$ is the *commitment* , $e$ is the *challenge* and $z$ is the *response* of the prover.

The straight-forward attack vector is to recover $r$ from $a$ and use it to recover the *witness*. But since recovering $r$ from $a$ is an instance of the DLP in $\mathbb{F}_p$ *(Discrete Logarithm problem on a finite field)*, and DLP is considered a hard problem, then this approach is not feasible.

# LLL :

The key here is that the random generated number $r$ is bounded by $(1 << 200)$ or $2^{200}$ while the modulus q is much larger (256 bits), this tells us that we can treat the number $r$ as the error term in the *Hidden Number Problem* (HNP) equation, and with enough equation we may be able to recover the secret which is the *witness* using  *Lattice Reduction Technique* . So:

$$z = (r + w \cdot e) \bmod q$$
Becomes the HNP equation. we just need enough samples of $(z, e)$, it turns out 6 samples are enough. enough to recover the $w \bmod q$.

# CRT :

Doing this only gets the witness mod q, also note that we can do this over and over by closing the connection and restarting it, and of course with different primes. Thus allowing as to recover the full witness using *Chinese Remainder Theorem* (CRT) which states that given equations :

$$
x \equiv a_1 \pmod{m_1} \\
$$

$$
x \equiv a_2 \pmod{m_2} \\
$$

$$
\vdots \\
$$

$$
x \equiv a_k \pmod{m_k}
$$

One can recover $x$ Uniquely using CRT which is already implemented in sagemath, so the final script is this, its an extension of this script https://github.com/josephsurin/lattice-based-cryptanalysis/blob/main/examples/problems/hidden_number_problem.sage :

```python
from Crypto.Util.number import long_to_bytes

data = [{}] # this is got from the data script below

def hnp_example(q, proofs):
    B = 1 << 200
    T = []
    A = []
    for d in proofs:
        T.append(d["e"])
        A.append(d["z"])
    sol = hnp(q, T, A, B, verbose=True)
    print("Recovered solution:", sol)
    w_mod_q = sol % q
    return w_mod_q, q

reminders = []
modulues = []

for session in data:
    wq, mod = hnp_example(session["q"], session["proofs"])
    reminders.append(wq)
    modulues.append(mod)

W = crt(reminders, modulues)

print("Recovered w bitlen:", int(W).bit_length())
print("Recovered FLAG:")
print(long_to_bytes(W))
```
I used this repo [[https://github.com/josephsurin/lattice-based-cryptanalysis]] .

# DATA :

This is the script to get data from the server in python :
ChatGPT did good job here.

```python
from pwn import *
import re
import ast

HOST = "4786170ad621653c.chal.ctf.ae"
PORT = 443

def collect_all():
    sessions = []

    for S in range(40):
        print(f"[+] Starting session {S+1}/10")
        s = remote(HOST, PORT, ssl=True, sni=HOST)

        banner = s.recvuntil(b"[2] Exit").decode()

        # ---------------------------
        # Extract metadata
        # ---------------------------
        md = {}
        md["p"] = int(re.search(r"p = (\d+)", banner).group(1))
        md["q"] = int(re.search(r"q = (\d+)", banner).group(1))
        md["g"] = int(re.search(r"g = (\d+)", banner).group(1))
        md["y"] = int(re.search(r"y = (\d+)", banner).group(1))
        md["bitlen"] = int(re.search(r"hint: (\d+)", banner).group(1))
        md["proofs"] = []

        # ---------------------------
        # Get 6 proofs
        # ---------------------------
        for i in range(6):
            s.sendline(b"1")
            line = s.recvline_contains(b"proof").decode()

            # Extract dict {"a":..., "e":..., "z":...}
            proof_dict = ast.literal_eval(line.split("proof:")[1].strip())

            md["proofs"].append({
                "a": proof_dict["a"],
                "e": proof_dict["e"],
                "z": proof_dict["z"]
            })

        s.close()

        sessions.append(md)

    return sessions

if name == "main":
    data = collect_all()

    print("\n=== FIRST SESSION ===")
    print(data)

    print(f"\n[+] Total sessions collected: {len(data)}")
    print("[+] Each session contains its own parameters + 6 proofs.")

```
