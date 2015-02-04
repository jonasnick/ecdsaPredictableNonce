# ecdsaPredictableNonce
Breaks an ecdsa implementation that uses `secret xor message` as nonce and reuses `secret`. This requires 256 signatures.
In other words, every signature leaks 1 bit. 

A detailed explanation of the attack can be found in the
[explanation.pdf](https://github.com/jonasnick/ecdsaPredictableNonce/raw/master/explanation/explanation.pdf).

`main.go` is the implementation of an attack specifically against a vulnerable version of [github.com/obscuren/secp256k1-go](https://github.com/obscuren/secp256k1-go).
The obvious fix is to use the system's PRNG to generate the nonce just like the [original project by haltingstate](https://github.com/haltingstate/secp256k1-go).

