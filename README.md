# ecdsaPredictableNonce
Breaks an ecdsa implementation that uses `privKey xor message` as nonce. Recovering the full private key requires 256 signatures.
In other words, every signature leaks 1 bit. 
An detailed explanation of the attack can be found in the
[explanation.pdf](https://github.com/jonasnick/ecdsaPredictableNonce/raw/master/explanation/explanation.pdf).

`main.go` is the implementation of an attack specifically against a vulnerable version of [github.com/obscuren/secp256k1-go](https://github.com/obscuren/secp256k1-go).
It takes roughly 11 minutes for my 3.0Ghz processor to solve the system.
The obvious fix is to use the operating system's PRNG to generate the nonce just like the [original project by haltingstate](https://github.com/haltingstate/secp256k1-go).

