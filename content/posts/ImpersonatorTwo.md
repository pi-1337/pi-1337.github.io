
---
title: "ImpersonatorTwo"
date: 2026-02-03
draft: false
---

## It works 🎉

# Write-up for ImpersonatorTwo challenge from Ethernaut CTF

This challenge is a part of [The Ethernaut CTF](https://ethernaut.openzeppelin.com) and It is the 37th challenge.
This is the description of the challenge:

*The goal of this level is for you to steal all the funds from the contract.*

*Things that might help:*
- *Look carefully at the 2 signatures that the owner of the contract used to lock it and set the admin.*
# Prerequisites
- High level knowledge of ECC and ECDSA.
- familiarity with solidity code.

*if you are not familiar with ECC and ECDSA, I recommend you finish this course on [Cryptohack](https://cryptohack.org/courses/elliptic/course_details/).*
### code:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable} from "openzeppelin-contracts-08/access/Ownable.sol";
import {ECDSA} from "openzeppelin-contracts-08/utils/cryptography/ECDSA.sol";
import {Strings} from "openzeppelin-contracts-08/utils/Strings.sol";

contract ImpersonatorTwo is Ownable {
    using Strings for uint256;

    error NotAdmin();
    error InvalidSignature();
    error FundsLocked();

    address public admin;
    uint256 public nonce;
    bool locked;

    constructor() payable {}

    modifier onlyAdmin() {
        require(msg.sender == admin, NotAdmin());
        _;
    }

    function setAdmin(bytes memory signature, address newAdmin) public {
        string memory message = string(abi.encodePacked("admin", nonce.toString(), newAdmin));
        require(_verify(hash_message(message), signature), InvalidSignature());
        nonce++;
        admin = newAdmin;
    }

    function switchLock(bytes memory signature) public {
        string memory message = string(abi.encodePacked("lock", nonce.toString()));
        require(_verify(hash_message(message), signature), InvalidSignature());
        nonce++;
        locked = !locked;
    }

    function withdraw() public onlyAdmin {
        require(!locked, FundsLocked());
        payable(admin).transfer(address(this).balance);
    }

    function hash_message(string memory message) public pure returns (bytes32) {
        return ECDSA.toEthSignedMessageHash(abi.encodePacked(message));
    }

    function _verify(bytes32 hash, bytes memory signature) internal view returns (bool) {
        return ECDSA.recover(hash, signature) == owner();
    }
}
```
# Code Analysis

It looks like a challenge where we have to somehow bypass the ECDSA verification process, which we know is *impossible* unless there is a problem in the implementation.

Why *impossible*, you ask ?
Well It is because ECDSA is based on *Elliptic Curve Cryptography* which is one of modern public-key cryptosystems in modern cryptography. And It is considered secure because of the Hardness of the EC-DLP problem (Elliptic Curve Discrete Log Problem).

Elliptic Curve Discrete Log Problem is the problem defined as:

$$
\text{given two Elliptic Curve points } G \text{ and } P \text{ in an Elliptic Curve } E
$$

$$
\text{find d such that } 
$$

$$
P = d * G 
$$

$$
\text{where } * \text{ denotes the scalar multiplication on } E 
$$

$$
\text{This problem is considered and believed to be a Hard problem, more precisely and formaly, It is an NP problem.}
$$

The secret behind this challenge is the two signatures signed by owner of the contract. How do i know that ?
Well the description says "*Look carefully at the 2 signatures that the owner of the contract used to lock it and set the admin*".

This is a hint !!
So I created an instance and went to the explorer "*explorer*/tx/<TX_HASH>/advanced#internal", to see the details of instance creation TX, in order to see the two signatures used for both unlocking and setting the admin.
(*TX_HASH is the hash of the transaction of the creation of the instance. I got it from the internal transactions of the created instance.*)

here are the two signatures the owner signed :

```
	Function: switchLock(bytes signature) ***
	
	MethodID: 0xfd0268fb
	[0]:  0000000000000000000000000000000000000000000000000000000000000020
	[1]:  0000000000000000000000000000000000000000000000000000000000000041
	[2]:  e5648161e95dbf2bfc687b72b745269fa906031e2108118050aba59524a23c40
	[3]:  70026fc30e4e02a15468de57155b080f405bd5b88af05412a9c3217e028537e3
	[4]:  1b00000000000000000000000000000000000000000000000000000000000000
```

```
	Function: setAdmin(bytes domain_,address newAdmin) ***
	
	MethodID: 0x865fc3f3
	[0]:  0000000000000000000000000000000000000000000000000000000000000040
	[1]:  000000000000000000000000ada4affe581d1a31d7f75e1c5a3a98b2d4c40f68
	[2]:  0000000000000000000000000000000000000000000000000000000000000041
	[3]:  e5648161e95dbf2bfc687b72b745269fa906031e2108118050aba59524a23c40
	[4]:  4c3ac03b268ae1d2aca1201e8a936adf578a8b95a49986d54de87cd0ccb68a79
	[5]:  1b00000000000000000000000000000000000000000000000000000000000000
```

I kept looking at this for a while, then I instantly noticed the disaster, repeated $r$ ???

But what is $r$ ?

$r$ is the x-coordinate of $k*G$

$$
r = x(k \cdot G), \quad
$$

$$
\text{where $k$ is the nonce of the signature.}
$$

$$
\text{For two $r$ values ($r_1, r_2$) to be equal:}
$$

$$
x(k_1 \cdot G) = x(k_2 \cdot G), \quad
$$

$$
\text{where $x()$ is the x-coordinate of the point.}
$$


Just to be clear, this does not necessarily mean that the nonce is repeated, the two nonce might just be opposites of each other 

$$
k1 = -k2 \mod n
$$

$$
\text{where n is the order of Ellpitic Curve Secp256k1 used in Bitcoin and Ethereum}
$$

but since the two v's are equal : 

$$(v1 = v2)$$

This settles it !! the nonces are the same $k_1 = k_2$.
Why ? Because these two tell us basically if point is above the half of the order.
TL:DR: same $r$ and same $v$ means same $k$.

Which is a thing you never do in ECDSA, it is a famous security problem in ECDSA.

Nonce reuse is such a big deal because for different s1 and s2 if r1 = r2, one can efficiently recover the PRIVATE key of the signer
Meaning the attacker can actually sign ANY transaction in the name of the victim, for example stealing all funds anytime.

### Why is nonce reuse a probelm ?

This is the signing equation of ECDSA :

$$
s_i = k_i^{-1}(z_i + r_i.x)
$$

$$
\text{where }z_i\text{ is the hash of a message being signed }m_i
$$

$$
\text{given two such equations where the r and k are repeated :}
$$

$$
s_1 \equiv k^{-1}.(z_1 + r.x) \pmod{n}
$$

$$
s_2 \equiv k^{-1}.(z_2 + r.x) \pmod{n}
$$

It is possible to recover $k$, which is dangerous, here is why : 

$$
\text{since k is reused in the two signatures.}
$$

$$
\text{recovery of the nonce }k :
$$

$$
(1):
s_1 \equiv k^{-1}.(z_1 + r.x) \pmod{n}
$$

$$
s_2 \equiv k^{-1}.(z_2 + r.x) \pmod{n}
$$

$$
\iff\ 
k.s_1 \equiv z_1 + r.x \pmod{n}
$$

$$
k.s_2 \equiv z_2 + r.x \pmod{n}
$$

$$
\iff\ 
k.(s_1 - s_2) \equiv z_1 + r.x - z_2 - r.x \pmod{n}
$$

$$
\iff\ 
k.(s_1 - s_2) \equiv z_1 - z_2 \pmod{n}
$$

$$
\iff\ 
k \equiv (z_1 - z_2).(s_1 - s_2)^{-1} \pmod{n}
$$

As you can see above, efficient recovery of the nonce key, now what ?
Next is the private key of the signer (the owner of the contract):

$$
\text{now we already calculated } k
$$

$$
\text{recovery of the private key }x :
$$

$$
(1):
s_1 \equiv k^{-1}.(z_1 + r.x) \pmod{n}
$$

$$
s_2 \equiv k^{-1}.(z_2 + r.x) \pmod{n}
$$

$$
\iff\ 
k.s_1 \equiv z_1 + r.x \pmod{n}
$$

$$
k.s_2 \equiv z_2 + r.x \pmod{n}
$$

$$
\iff\ 
k.s_1 -  z_1 \equiv r.x \pmod{n}
$$

$$
k.s_2 -  z_2 \equiv r.x \pmod{n}
$$

$$
\iff\ 
r.x \equiv k.s_1 - z_1 \pmod{n}
$$

$$
r.x \equiv k.s_2 - z_2 \pmod{n}
$$

$$
\iff\ 
x \equiv (k.s_1 - z_1).r^{-1} \pmod{n}
$$

$$
x \equiv (k.s_2 - z_2).r^{-1} \pmod{n}
$$

Now there you have it, two ways to calculate the private key.

So now that we know the vulnerability, and the exploit, it is time to script.
We are gonna use foundry scripts in the solve, but because there is a lot of math here, we gonna need to use Python or much better Sagemath.
### Scripting

First is the Sagemath script that recovers the private key :

```python
# SECP256K1
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # Prime modulus
a = 0  # Curve parameter a for secp256k1
b = 7  # Curve parameter b for secp256k1
G_x = 0x79BE667EF9DCBBAC55A62DAD8B8D8D1D7D20A1B395B6B5D4A82A2F5D4C9D75E9  # Base point G_x
G_y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199E48B6B6CC0D2007  # Base point G_y

E = EllipticCurve(GF(p), [a, b])

G = E(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
n = G.order()

def recoverPrivateKey(r, s1, s2, z1, z2):
    """
    recovers private key and nonce from two signatures with the same nonce
    
    r_i = k_i.G
    s_i = k_i(z_i + r_i.x)
    
    """

    k = ((z1 - z2)*pow(s1-s2, -1, n)) % n

    privatekey1 = ((s1*k-z1) * pow(r, -1, n)) % n
    privatekey2 = ((s2*k-z2) * pow(r, -1, n)) % n
    
    # everything is good
    assert privatekey1 == privatekey2
    
    return k, privatekey2


print("==== sanity check ====")

x = 31415926535897963238
k = 123456789
r = int((k*G).xy()[0])
z1 = 789456123545467878654
s1 = ((z1 + r*x)*pow(k, -1, n)) % n

z2 = 456789321654654798954
s2 = ((z2 + r*x)*pow(k, -1, n)) % n
    
print(recoverPrivateKey(r, s1, s2, z1, z2))


print("==== actual private key recovery ====")

r2 = 0xe5648161e95dbf2bfc687b72b745269fa906031e2108118050aba59524a23c40;
s2 = 0x70026fc30e4e02a15468de57155b080f405bd5b88af05412a9c3217e028537e3;
v2 = 27;

r1 = 0xe5648161e95dbf2bfc687b72b745269fa906031e2108118050aba59524a23c40;
s1 = 0x4c3ac03b268ae1d2aca1201e8a936adf578a8b95a49986d54de87cd0ccb68a79;
v1 = 27;

# I got these from foundry script below,
# keep reading to understand how i got them
z1 = 0x6a0d6cd0c2ca5d901d94d52e8d9484e4452a3668ae20d63088909611a7dccc51
z2 = 0x937fa99fb61f6cd81c00ddda80cc218c11c9a731d54ce8859cb2309c77b79bf3

k, privatekey = recoverPrivateKey(r1, s1, s2, z1, z2)

print((k*G).xy()[0] == r1)


privatekey = hex(privatekey)
print(f"{k=}")
print(f"{privatekey=}")
```

Running it gives us:
 ```
 ==== sanity check ====
(123456789, 31415926535897963238)
==== actual private key recovery ====
True
k=115792089237316195423570985008687907852837564279074904382605163141518161463000
privatekey='0x10a6891de55baf453d66c5faede86eabccf93f3d284540d205f24207670855cc'
 ```

Note: the privatekey we just got is the actual private key of the wallet, so we really hacked the wallet of the owner, if we add an account in metamask with this private key and see the public key, it's gonna be the same as the owner of the contract (*we can even transfer ownership*).

Now for the Foundry script : 

Note: to get $z_1$ and $z_2$ that are not stored on the Blockchain, we have to go back in time, I went to etherscan and activate "advanced mode", and seen the the function calls done in the instance creation transaction, and to get the hashes of the messages, I had to know what function took effect the first, it turns out that the function at the top is the last executed :

![etherscan](etherscan.webp)

In this example, this means that the *switchLock* function is executed after *setAdmin*.
Why is this important ?
Because the call to these two function increments the *nonce* state variable which changes the hash of the message being signed (nonce here is not $k$ !!!!!!).

So now if the order of signing that the owner did is *setAdmin* then *switchLock*, this means we have to the same thing but in the opposite order like this:

```solidity
uint256 nonce = instance.nonce(); // this is the current nonce of the contract

nonce--;
address newAdmin = instance.admin();
string memory message1 = string(abi.encodePacked("admin", Strings.toString(nonce), newAdmin));
bytes32 z1 = instance.hash_message(message1);

nonce--;
string memory message2 = string(abi.encodePacked("lock", Strings.toString(nonce)));
bytes32 z2 = instance.hash_message(message2);

console.logBytes32(z1);
console.logBytes32(z2);
```

Now we can get the *deterministic* hashes of the two messages the owner signed.
Which we will pass to the Sagemath script to recover the private key, and then sign a new message.

Now that we have the private key of the signer, we can do anything, one of them is stealing the funds from the contract.
Plan is to set my self as the admin, then unlock funds (*these two tasks both need signature forgery*).
After that we just withdraw funds from the contract.

```solidity

uint256 victimPrivateKey = 0x10a6891de55baf453d66c5faede86eabccf93f3d284540d205f24207670855cc;
// got from the Sagemath script

string memory message = string(abi.encodePacked("admin", Strings.toString(instance.nonce()), me));
(uint8 v, bytes32 r, bytes32 s) = vm.sign(victimPrivateKey, instance.hash_message(message));
bytes memory forgedSignature = bytes.concat(r, s, bytes1(v));

instance.setAdmin(forgedSignature, me);

message = string(abi.encodePacked("lock", Strings.toString(instance.nonce())));
(v, r, s) = vm.sign(victimPrivateKey, instance.hash_message(message));
forgedSignature = bytes.concat(r, s, bytes1(v));
instance.switchLock(forgedSignature);


console.logBytes32(bytes32(address(instance).balance));
instance.withdraw();
console.logBytes32(bytes32(address(instance).balance));

```

### Final Foundry Script

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import { ImpersonatorTwo} from "../src/ImpersonatorTwo.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract ImpersonatorTwoSolver is Script {

	ImpersonatorTwo public instance = ImpersonatorTwo(0x3239d91108EcD565Fde17BD6a7D68305FCA2E3AF);

	uint256 prv = vm.envUint("PRV");
	address me = vm.envAddress("PUB");

	function run() external {
		vm.startBroadcast(prv);

		// lock
		uint256 r2 = 0xe5648161e95dbf2bfc687b72b745269fa906031e2108118050aba59524a23c40;
		uint256 s2 = 0x70026fc30e4e02a15468de57155b080f405bd5b88af05412a9c3217e028537e3;
		uint256 v2 = 27;

		// setAdmin
		uint256 r1 = 0xe5648161e95dbf2bfc687b72b745269fa906031e2108118050aba59524a23c40;
		uint256 s1 = 0x4c3ac03b268ae1d2aca1201e8a936adf578a8b95a49986d54de87cd0ccb68a79;
		uint256 v1 = 27;


		// recovering the z's (hashes of signed messages)
		uint256 nonce = instance.nonce();
		nonce -= 2;

		string memory message2 = string(abi.encodePacked("lock", Strings.toString(nonce)));
		bytes32 z2 = instance.hash_message(message2);

		nonce++;

        address newAdmin = instance.admin();
		string memory message1 = string(abi.encodePacked("admin", Strings.toString(nonce), newAdmin));
        bytes32 z1 = instance.hash_message(message1);

		console.logBytes32(z1);
		console.logBytes32(z2);

		


		uint256 victimPrivateKey = 0x10a6891de55baf453d66c5faede86eabccf93f3d284540d205f24207670855cc; // got from the Sagemath script

		string memory message = string(abi.encodePacked("admin", Strings.toString(instance.nonce()), me));
		(uint8 v, bytes32 r, bytes32 s) = vm.sign(victimPrivateKey, instance.hash_message(message));
		bytes memory forgedSignature = bytes.concat(r, s, bytes1(v));
	
		instance.setAdmin(forgedSignature, me);

		message = string(abi.encodePacked("lock", Strings.toString(instance.nonce())));
		(v, r, s) = vm.sign(victimPrivateKey, instance.hash_message(message));
		forgedSignature = bytes.concat(r, s, bytes1(v));
		instance.switchLock(forgedSignature);
	

		console.logBytes32(bytes32(address(instance).balance)); // before
		instance.withdraw();
		console.logBytes32(bytes32(address(instance).balance)); // after
		
		vm.stopBroadcast();
	}

}
```

```
Script ran successfully.

== Logs ==
  0x6a0d6cd0c2ca5d901d94d52e8d9484e4452a3668ae20d63088909611a7dccc51
  0x937fa99fb61f6cd81c00ddda80cc218c11c9a731d54ce8859cb2309c77b79bf3
  0x00000000000000000000000000000000000000000000000000038d7ea4c68000
  0x0000000000000000000000000000000000000000000000000000000000000000

## Setting up 1 EVM.

==========================

Chain 11155111

Estimated gas price: 1.891920509 gwei

Estimated total gas used for script: 158466

Estimated amount required: 0.000299805075379194 ETH
```

Notes: 
 - In the logs, the first 32 bytes are the hash of the first message signed by the owner $z_1$ and the second is the second hash $z_2$.
 - The third and forth 32 bytes are the balances of the contract before and after the withdraw respectively.
 - The forth is 0x0 meaning the drain of the contract was a success.

### Submitting the Instance :

*Congratulations! You've successfully unlocked another secret of the elliptic curve signatures!*

*It is very important to never reuse the same nonce for two signatures. RFC6979 defines a deterministic digital signature generation procedure which removes the risks of reusing twice the same nonce.*

