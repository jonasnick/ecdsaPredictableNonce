# ecdsaPredictableNonce
Breaks an ecdsa implementation that uses `secret xor message` as nonce and reuses `secret`. This requires 512 signatures.
An detailed explanation of the attack can be found in the
[explanation.pdf](explanation/explanation.pdf).

`main.go` is the implementation of an attack specifically against a vulnerable version of [github.com/obscuren/secp256k1-go](https://github.com/obscuren/secp256k1-go).

