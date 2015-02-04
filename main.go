package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/obscuren/secp256k1-go"
)

func fill(b byte) []byte {
	p_bytes := make([]byte, 32)
	for i := range p_bytes {
		p_bytes[i] = b
	}
	return p_bytes
}

//FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
var p = func() *big.Int {
	p_bytes := fill(0xff)
	p_bytes[32-5] = 0xfe
	p_bytes[32-2] = 0xfc
	p_bytes[32-1] = 0x2f

	return byteToBig(p_bytes)
}()

var n_bytes = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}
var n = byteToBig(n_bytes)

func byteToBig(b []byte) *big.Int {
	return big.NewInt(0).SetBytes(b)
}

func additiveInv(x *big.Int) *big.Int {
	return big.NewInt(0).Sub(n, x)
}
func additiveInvWith(x *big.Int, n *big.Int) *big.Int {
	return big.NewInt(0).Sub(n, x)
}

func bitVector(x *big.Int, numBytes int) []*big.Int {
	l := len(x.Bytes())
	bV := make([]*big.Int, numBytes*8)
	for i := 0; i < numBytes; i++ {
		var b byte
		if i >= l {
			b = byte(0)
		} else {
			b = x.Bytes()[l-i-1]
		}
		for bit, mask := 0, byte(1); bit < 8; bit, mask = bit+1, mask<<1 {
			j := 8*numBytes - (8*i + int(bit)) - 1
			//j := i
			if b&mask != 0 {
				bV[j] = big.NewInt(1)
			} else {
				bV[j] = big.NewInt(0)
			}
		}
	}
	return bV
}

func bigIntFromBitVector(v []*big.Int) *big.Int {
	acc := big.NewInt(0)
	l := len(v)
	for i, b := range v {
		s := big.NewInt(0).Mul(b, big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(l-i-1)), nil))
		acc.Add(acc, s)
	}
	return big.NewInt(0).Mod(acc, n)
}

// s = k^-1(z + rd) mod n
func checkECDSA(r, s, z, seckey *big.Int) error {
	k := big.NewInt(0).Xor(seckey, z)
	a := big.NewInt(0).ModInverse(k, n)
	rda := big.NewInt(0).Mod(big.NewInt(0).Mul(r, seckey), n)
	b := big.NewInt(0).Mod(big.NewInt(0).Add(z, rda), n)
	sNew := big.NewInt(0).Mod(big.NewInt(0).Mul(b, a), n)
	if bytes.Compare(sNew.Bytes(), s.Bytes()) != 0 {
		return errors.New("different s")
	}
	return nil
}

// negate s if our own ECDSA produces different s
func maybeNegateS(r, s, z, d_a *big.Int) *big.Int {
	if checkECDSA(r, s, z, d_a) != nil {
		s = additiveInv(s)
		// sanity check
		if err := checkECDSA(r, s, z, d_a); err != nil {
			panic("failed potentially inverse")
		}
	}
	return s
}

// adapted from rosetta stone for finite fields
func GaussPartial(a0 [][]*big.Int, b0 []*big.Int, coefMod *big.Int) ([]*big.Int, error) {
	// make augmented matrix
	m := len(b0)
	a := make([][]*big.Int, m)
	for i, ai := range a0 {
		row := make([]*big.Int, m+1)
		copy(row, ai)
		row[m] = b0[i]
		a[i] = row
	}
	// WP algorithm from Gaussian elimination page
	// produces row-eschelon form
	for k := range a {
		// Find pivot for column k:
		iMax := k
		max := a[k][k]
		for i := k + 1; i < m; i++ {
			abs := a[i][k]
			if abs.Cmp(max) > 0 {
				iMax = i
				max = abs
			}
		}
		if a[iMax][k].Cmp(big.NewInt(0)) == 0 {
			return nil, errors.New("singular")
		}
		// swap rows(k, i_max)
		a[k], a[iMax] = a[iMax], a[k]
		// Do for all rows below pivot:
		for i := k + 1; i < m; i++ {
			// Do for all remaining elements in current row:
			for j := k + 1; j <= m; j++ {
				a[i][j] = big.NewInt(0).Mod(big.NewInt(0).Add(a[i][j], additiveInvWith(big.NewInt(0).Mul(a[k][j], big.NewInt(0).Mul(a[i][k], big.NewInt(0).ModInverse(a[k][k], coefMod))), coefMod)), coefMod)
			}
			// Fill lower triangular matrix with zeros:
			a[i][k] = big.NewInt(0)
		}
	}
	// end of WP algorithm.
	// now back substitute to get result.
	x := make([]*big.Int, m)
	for i := m - 1; i >= 0; i-- {
		x[i] = a[i][m]
		for j := i + 1; j < m; j++ {
			x[i] = big.NewInt(0).Mod(big.NewInt(0).Add(x[i], additiveInvWith(big.NewInt(0).Mul(a[i][j], x[j]), coefMod)), coefMod)
		}
		x[i] = big.NewInt(0).Mod(big.NewInt(0).Mul(x[i], big.NewInt(0).ModInverse(a[i][i], coefMod)), coefMod)
	}
	return x, nil
}

func alpha(s, z *big.Int) *big.Int {
	a := big.NewInt(0).Mod(big.NewInt(0).Add(s, additiveInv(big.NewInt(1))), n)
	b := big.NewInt(0).Mod(big.NewInt(0).Mul(a, z), n)
	return b
}

func beta(r, s *big.Int, z_bits []*big.Int, i int) *big.Int {
	a := big.NewInt(0)
	l := len(z_bits)

	if z_bits[i].Cmp(big.NewInt(1)) == 0 {
		a = s
	} else {
		a = additiveInv(s)
	}
	exp := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(l-i-1)), nil)
	return big.NewInt(0).Mod(big.NewInt(0).Mul(big.NewInt(0).Add(a, r), exp), n)
}

func checkEquation(r, s, z, da *big.Int) error {
	z_bits := bitVector(z, 32)
	da_bits := bitVector(da, 32)
	a := alpha(s, z)
	sum := big.NewInt(0)

	for i, dab := range da_bits {
		a := big.NewInt(0).Mul(dab, beta(r, s, z_bits, i))
		sum.Add(sum, a)
	}

	sum.Mod(sum, n)
	if bytes.Compare(sum.Bytes(), a.Bytes()) != 0 {
		fmt.Println(sum)
		fmt.Println(a)
		log.Fatal("check derivation 4")
	}
	return nil
}

func signatures(n int) ([]*big.Int, []*big.Int, []*big.Int) {
	rs := make([]*big.Int, n)
	ss := make([]*big.Int, n)
	zs := make([]*big.Int, n)

	_, seckey := secp256k1.GenerateKeyPair()
	//seckey := []byte{78, 210, 169, 208, 35, 22, 85, 33, 213, 206, 82, 33, 137, 76, 85, 234, 82, 174, 175, 134, 63, 181, 37, 131, 79, 227, 32, 12, 178, 209, 97, 164}
	fmt.Println("seckey", fmt.Sprintf("%X", seckey))

	for i := 0; i < n; i++ {
		z := secp256k1.RandByte(32)
		sig, err := secp256k1.Sign(z, seckey)
		if err != nil {
			log.Fatal(err)
		}
		r_sig := sig[0:32]
		s_sig := sig[32:64]
		rs[i] = byteToBig(r_sig)
		zs[i] = byteToBig(z)

		// TODO:
		ss[i] = maybeNegateS(rs[i], byteToBig(s_sig), zs[i], byteToBig(seckey))

	}
	return rs, ss, zs
}

func row(r, s, z *big.Int) (*big.Int, []*big.Int) {
	z_bits := bitVector(z, 32)
	l := len(z_bits)
	c := make([]*big.Int, l)
	for i := range z_bits {
		c[i] = beta(r, s, z_bits, i)
	}
	return alpha(s, z), c
}

func generate_rows(rs, ss, zs []*big.Int) ([]*big.Int, [][]*big.Int) {
	alphas := make([]*big.Int, 0)
	coefs := make([][]*big.Int, 0)
	for i := range rs {
		a, c := row(rs[i], ss[i], zs[i])
		alphas = append(alphas, a)
		coefs = append(coefs, c)
	}
	return alphas, coefs
}

func recoverKey(rs, ss, zs []*big.Int) *big.Int {
	alphas, coefs := generate_rows(rs, ss, zs)
	x, err := GaussPartial(coefs, alphas, n)
	if err != nil {
		log.Fatal(err)
	}
	return bigIntFromBitVector(x)
}

func main() {
	rs, ss, zs := signatures(256)
	d := recoverKey(rs, ss, zs)
	fmt.Println("recovered key", fmt.Sprintf("%X", d))
}
