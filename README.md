# Ethereum Bug Bounty Submission: Predictable ECDSA Nonce
Breaks an ecdsa implementation that uses `privKey xor message` as nonce. Recovering the full private key requires 256 signatures.
In other words, every signature leaks 1 bit. 
A detailed explanation of the attack can be found in the
[explanation.pdf](https://github.com/jonasnick/ecdsaPredictableNonce/raw/master/explanation/explanation.pdf).

`main.go` is the implementation of an attack specifically against a vulnerable version of [github.com/obscuren/secp256k1-go](https://github.com/obscuren/secp256k1-go) and thus also against [go-ethereum](https://github.com/ethereum/go-ethereum) .
It takes roughly 11 minutes for my 3.0Ghz processor to solve the system.
The obvious fix is to use the operating system's PRNG to generate the nonce just like the [original project by haltingstate](https://github.com/haltingstate/secp256k1-go).

Caveat
---
In its current form, this attack does not directly work against github.com/obscuren/secp256k1-go package.
The reason for this is that in order to prevent `s`-malleability, libsecp256k1 enforces an `s` that is smaller than `curve_order/2`.
If libsecp256k1 computes an `s` that is bigger it is negated, which essentially has the effect that the message is signed using the negative of the original nonce.
Because this attack gets only 1 bit from each signature generated from the textbook algorithm and we don't know if `nonce` or `-nonce` has been used, the attacker looses 1 bit and thus learns nothing.
See [this line] (https://github.com/jonasnick/ecdsaPredictableNonce/blob/master/main.go#L215) for the cheat that is used in order to ensure using the non-negated nonce.

Thanks to [Pieter Wuille](https://github.com/sipa) for some helpful discussion.
