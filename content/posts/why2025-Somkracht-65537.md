
---
title: "why2025-Somkracht-65537"
date: 2026-02-03
draft: false
---

## 🎯 The Challenge

This is a fun RSA challenge with an interesting twist! Instead of factoring the modulus \(N\), we recover the message directly using a clever insight.

### Given:

#### Public Key:
$$
\((e, N)\)
$$
#### Ciphertext (encrypted in regular RSA):
$$
ct_1 = m^e \bmod N
$$

#### Additionnal leak (this is unusual in secure RSA):
$$
ct_2 = m^{p+q} \bmod N
$$

> **Note:** Primes \(p, q\) are huge, so factoring \(N\) is infeasible, but the leak opens a new attack vector.

---

## 💡 The Solution Approach

### Euler's Totient:

$$
\phi(N) = (p-1)(q-1) = pq - p - q + 1 = N + 1 - (p + q)
$$

### Euler's theorem:

$$
a^{\phi(N)} \equiv 1 \pmod{N} \implies a^{\phi(N) + 1} \equiv a \pmod{N}
$$

### The trick:

Express \(N\) as

$$
N = \alpha e + \beta, \quad \text{with } \beta < e
$$

Define

$$
\gamma = e - \beta - 1
$$

so

$$
e = \gamma + \beta + 1
$$

### Key calculation:

$$
m_{\to \gamma}  \equiv ct_1^{\alpha + 1} \cdot ct_2^{-1} \bmod N \\
$$

$$
\equiv m^{e(\alpha + 1)} \cdot m^{-(p+q)} \bmod N \\
$$

$$
\equiv m^{e\alpha + e - (p+q)} \bmod N \\
$$

$$
\equiv m^{N + \gamma + 1 - (p+q)} \bmod N \\
$$

$$
\equiv m^{\phi(N) + \gamma} \bmod N \\
$$

$$
\equiv m^{\phi(N)} \cdot m^{\gamma} \bmod N \\
$$

$$
\equiv 1 \cdot m^{\gamma} \bmod N \\
$$

$$
\equiv m^{\gamma} \bmod N
$$

---

### Recovering \(m\) with Bézout’s lemma:

Since

$$
\gcd(e, \gamma) = 1
$$

there exist integers \(x, y\) with

$$
e x + \gamma y = 1
$$

Thus

$$
m = (ct_1^x \cdot m_{\to \gamma}^y) \bmod N
$$

because

$$
(ct_1^x \cdot m_{\to \gamma}^y) \bmod N \equiv (m^{e x} \cdot m^{\gamma y}) \bmod N \\
$$

$$
\equiv m^{e x + \gamma y} \bmod N \\
$$

$$
\equiv m^1 \bmod N \\
$$

$$
\equiv m \bmod N
$$

---

## 🖥️ Implementation

```python
from Crypto.Util.number import long_to_bytes

# Given
e = 65537
N = <very_large_number>
ct1 = <ciphertext_1>
ct2 = <ciphertext_2>

alpha = N // e
beta = N % e
gamma = e - beta - 1

print(f"alpha = {alpha}, beta = {beta}, gamma = {gamma}")

m_to_gamma = (pow(ct1, alpha + 1, N) * pow(ct2, -1, N)) % N

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return (gcd, x, y)

gcd, x, y = extended_gcd(e, gamma)

flag = (pow(ct1, x, N) * pow(m_to_gamma, y, N)) % N

print("Recovered flag:", long_to_bytes(flag))
