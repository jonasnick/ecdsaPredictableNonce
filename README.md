# ecdsaPredictableNonce
Breaks an ecdsa implementation that uses `secret xor message` as nonce. This requires 512 signatures.
An detailed explanation of the attack can be found in the
[explanation.pdf](explanation/explanation.md).

`main.go` is the implementation of an attack specifically against a vulnerable version of [github.com/obscuren/secp256k1-go](https://github.com/obscuren/secp256k1-go).

