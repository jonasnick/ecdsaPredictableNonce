package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/big"

	//"github.com/jonasnick/ecdsaPredictableNonce/big"

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

//(1-s)z(s-r)^-1
func fn1(r, s, z *big.Int) *big.Int {
	a := big.NewInt(1)
	a = big.NewInt(0).Mod(big.NewInt(0).Add(a, additiveInv(s)), n)
	a = big.NewInt(0).Mod(big.NewInt(0).Mul(a, big.NewInt(0).Mod(z, n)), n)
	b := big.NewInt(0).ModInverse(big.NewInt(0).Mod(big.NewInt(0).Add(s, additiveInv(r)), n), n)
	a = big.NewInt(0).Mod(big.NewInt(0).Mul(a, b), n)
	return a
}

//2s(s-r)^-1
func fn2(r, s *big.Int) *big.Int {
	a := big.NewInt(0).ModInverse(big.NewInt(0).Mod(big.NewInt(0).Add(s, additiveInv(r)), n), n)
	a = big.NewInt(0).Mod(big.NewInt(0).Mul(big.NewInt(2), a), n)
	a = big.NewInt(0).Mod(big.NewInt(0).Mul(s, a), n)
	return a
}

// fn1 * (1-fn2)^-1
// returns a slice of r and a slice of s
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
		// have to negate s if it has been negated in the secp256k1 library
		// requires knowledge seckey here, but if there was a ModSqrt in the big package
		// we could determine if s has to be negated by computing r.y and then checking if
		// it is odd
		ss[i] = maybeNegateS(rs[i], byteToBig(s_sig), zs[i], byteToBig(seckey))
		//ss[i] = byteToBig(s_sig)
		if ss[i] == nil {
			panic("nil")
		}

	}
	return rs, ss, zs
}

// s = k^-1(z + rd) mod n
func checkECDSA(seckey, r, s, z *big.Int) {
	k := big.NewInt(0).Xor(seckey, z)
	a := big.NewInt(0).ModInverse(k, n)
	rda := big.NewInt(0).Mod(big.NewInt(0).Mul(r, seckey), n)
	b := big.NewInt(0).Mod(big.NewInt(0).Add(z, rda), n)
	sNew := big.NewInt(0).Mod(big.NewInt(0).Mul(b, a), n)
	//if sNew.Cmp(big.NewInt(0).Div(n, big.NewInt(2))) > 0 {
	//sNew = additiveInv(sNew)
	//}
	if bytes.Compare(sNew.Bytes(), s.Bytes()) != 0 {
		fmt.Printf("sNew %#X\n", sNew)
		fmt.Printf("s %#X\n", s)
		log.Fatal("check not positive")
	}

}

func hash(data []byte) []byte {
	bf := sha256.Sum256(data)
	b := bf[0:32]
	return b
}

// d_a = fn1 + fn2*(d_A and z)
func checkEquation1(r, s, z, d_a *big.Int) error {
	a := fn1(r, s, z)
	b := fn2(r, s)
	k := big.NewInt(0).Mod(big.NewInt(0).And(z, d_a), n)
	c := big.NewInt(0).Mod(big.NewInt(0).Mul(k, b), n)
	d := big.NewInt(0).Mod(big.NewInt(0).Add(a, c), n)
	if bytes.Compare(d.Bytes(), d_a.Bytes()) != 0 {
		//fmt.Println("d", d)
		//fmt.Println("d_a", d_a)
		return errors.New("error: d != d_a")
	}
	return nil

}

// alpha = fn1(s', r', z') - fn1(s, r, z)
func alpha(r, s, z, rp, sp, zp *big.Int) *big.Int {
	a1 := fn1(rp, sp, zp)
	a2 := fn1(r, s, z)
	a3 := big.NewInt(0).Mod(big.NewInt(0).Add(a1, additiveInv(a2)), n)
	return a3
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

// alpha = fn2(r, s)* (da & z) - fn2(r', s') * (da & zp)
func checkEquation2a(a, r, s, z, rp, sp, zp, da *big.Int) error {
	a1 := big.NewInt(0).Mod(big.NewInt(0).And(z, da), n)
	a2 := big.NewInt(0).Mod(big.NewInt(0).And(zp, da), n)
	b1 := fn2(r, s)
	b2 := fn2(rp, sp)
	c1 := big.NewInt(0).Mod(big.NewInt(0).Mul(b1, a1), n)
	c2 := big.NewInt(0).Mod(big.NewInt(0).Mul(b2, a2), n)
	//x := big.NewInt(0).Mod(big.NewInt(0).Add(c1, additiveInv(c2)), n)
	d1 := big.NewInt(0).Mod(big.NewInt(0).Add(fn1(r, s, z), c1), n)
	d2 := big.NewInt(0).Mod(big.NewInt(0).Add(fn1(rp, sp, zp), c2), n)
	if bytes.Compare(d1.Bytes(), d2.Bytes()) != 0 {
		fmt.Println(d1)
		fmt.Println(d2)
		log.Fatal("(1) failied in derivation 2a")
		return nil
	}

	f := big.NewInt(0).Mod(big.NewInt(0).Add(additiveInv(c2), c1), n)
	if bytes.Compare(a.Bytes(), f.Bytes()) != 0 {
		fmt.Println(d1)
		fmt.Println(d2)
		log.Fatal("(2) failied in derivation 2a")
		return nil
	}

	return nil
}

// alpha == sum d_i * 2^i * (fn2(r, s) z_i - fn2(r', s') z_i'
func checkEquation2b(a, r, s, z, rp, sp, zp, da *big.Int) error {
	z_bits := bitVector(z, 32)
	zp_bits := bitVector(zp, 32)
	da_bits := bitVector(da, 32)
	l := len(da_bits)
	sum := big.NewInt(0)
	b1 := fn2(r, s)
	b2 := fn2(rp, sp)

	for i, dab := range da_bits {
		k1 := big.NewInt(0).Mul(z_bits[i], b1)
		k2 := big.NewInt(0).Mul(zp_bits[i], b2)
		k3 := big.NewInt(0).Add(k1, additiveInv(k2))
		x1 := big.NewInt(0).Mod(big.NewInt(0).Mul(dab, k3), n)
		exp := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(l-i-1)), nil)
		x2 := big.NewInt(0).Mod(big.NewInt(0).Mul(x1, exp), n)
		sum = big.NewInt(0).Mod(big.NewInt(0).Add(sum, x2), n)
	}

	sum.Mod(sum, n)
	if bytes.Compare(sum.Bytes(), a.Bytes()) != 0 {
		fmt.Println(sum)
		fmt.Println(a)
		log.Fatal("check derivation 2b")
	}
	return nil
}

func checkEquation3(a1, b1, a2, b2, d_a *big.Int) error {
	//fmt.Println(a1.Bytes(
	a := big.NewInt(0).Or(a1, a2)
	b := big.NewInt(0).Or(b1, b2)
	c := big.NewInt(0).And(b, d_a)
	if bytes.Compare(a.Bytes(), c.Bytes()) != 0 {
		fmt.Println("a", a.Bytes())
		fmt.Println("b", b.Bytes())
		fmt.Println("c", c.Bytes())
		return errors.New("a != b^d_a")
	}
	return nil
}

// negate s if checkEquation1 fails
func maybeNegateS(r, s, z, d_a *big.Int) *big.Int {
	if checkEquation1(r, s, z, d_a) != nil {
		s = additiveInv(s)
		// sanity check
		if err := checkEquation1(r, s, z, d_a); err != nil {
			panic("failed potentially inverse")
		}
	}
	return s
}

func secp256k1_f(x *big.Int) *big.Int {
	y := big.NewInt(0).Exp(x, big.NewInt(3), p)
	y = big.NewInt(0).Mod(big.NewInt(0).Add(y, big.NewInt(7)), p)
	//y = big.NewInt(0).ModSqrt(y, p)
	return y
}

func isOdd(x *big.Int) bool {
	m := big.NewInt(2)
	mod := big.NewInt(0).Mod(x, m)
	return big.NewInt(0).Cmp(mod) < 0
}

func maybeNegateS2(r, s, z, d_a *big.Int, recid byte) *big.Int {
	y := secp256k1_f(r)
	fmt.Println(y)
	fmt.Println(recid, isOdd(y))
	if (recid > 0 && !isOdd(y)) || (recid == 0 && isOdd(y)) {
		// 0 false
		// 0
		fmt.Println("inv")
		s = additiveInv(s)

	}
	if err := checkEquation1(r, s, z, d_a); err != nil {
		panic("failed second potentially inverse")
	}
	return s
}

// adapted from rosetta stone
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
		//if max.Cmp(big.NewInt(0).Div(coefMod, big.NewInt(2))) > 0 {
		//max = additiveInvWith(max, coefMod)
		//}
		for i := k + 1; i < m; i++ {
			abs := a[i][k]
			//if abs.Cmp(big.NewInt(0).Div(coefMod, big.NewInt(2))) > 0 {
			//abs = additiveInvWith(abs, coefMod)
			//}

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
				//fmt.Println(i, j, a[i][j])
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

func row(r, s, z, rp, sp, zp *big.Int) (*big.Int, []*big.Int) {
	z_bits := bitVector(z, 32)
	zp_bits := bitVector(zp, 32)
	l := len(z_bits)
	a := alpha(r, s, z, rp, sp, zp)
	b1 := fn2(r, s)
	b2 := fn2(rp, sp)
	c := make([]*big.Int, l)

	//fmt.Println("bits", len(z_bits), len(zp_bits))

	for i := range z_bits {
		k1 := big.NewInt(0).Mul(z_bits[i], b1)
		k2 := big.NewInt(0).Mul(zp_bits[i], b2)
		k3 := big.NewInt(0).Add(k1, additiveInv(k2))
		exp := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(l-i-1)), nil)
		c[i] = big.NewInt(0).Mod(big.NewInt(0).Mul(k3, exp), n)
	}
	return a, c
}

func collectRows(rs, ss, zs []*big.Int) ([]*big.Int, [][]*big.Int) {
	num := len(rs)
	numRows := num / 2
	//log.Println("numRows", numRows)
	alphas := make([]*big.Int, 0)
	coefs := make([][]*big.Int, 0)
	for i := 0; i < numRows; i += 1 {
		r, s, z := rs[2*i], ss[2*i], zs[2*i]
		r2, s2, z2 := rs[2*i+1], ss[2*i+1], zs[2*i+1]

		a, c := row(r, s, z, r2, s2, z2)
		alphas = append(alphas, a)
		coefs = append(coefs, c)
	}

	/* for i := 0; i < num; i += 1 {*/
	//for j := i + 1; j < num; j += 1 {
	//r, s, z := rs[i], ss[i], zs[i]
	//r2, s2, z2 := rs[j], ss[j], zs[j]

	//a, c := row(r, s, z, r2, s2, z2)
	//alphas = append(alphas, a)
	//coefs = append(coefs, c)
	//}
	/*}*/
	return alphas, coefs
}

func verifyGauss(alphas []*big.Int, coefs [][]*big.Int, x []*big.Int) error {
	for i, cs := range coefs {
		sum := big.NewInt(0)
		for j, c := range cs {
			foo := big.NewInt(0).Mod(big.NewInt(0).Mul(c, x[j]), n)
			sum = big.NewInt(0).Mod(big.NewInt(0).Add(sum, foo), n)
		}
		if sum.Cmp(alphas[i]) != 0 {
			fmt.Println("sum", sum)
			fmt.Println("alpha", alphas[i])
			return errors.New(fmt.Sprintf("verify gauss error at row %d", i))
		}
	}
	return nil
}

func recoverKey(rs, ss, zs []*big.Int) *big.Int {
	alphas, coefs := collectRows(rs, ss, zs)
	x, err := GaussPartial(coefs, alphas, n)
	if err != nil {
		log.Fatal(err)
	}
	return bigIntFromBitVector(x)
}

func main() {
	rs, ss, zs := signatures(512)
	//signatures(30)
	//d_a := byteToBig(seckey)
	d := recoverKey(rs, ss, zs)
	fmt.Println("recovered key", fmt.Sprintf("%X", d))

	/* s0 := maybeNegateS(rs[0], ss[0], zs[0], d_a)*/
	//s1 := maybeNegateS(rs[1], ss[1], zs[1], d_a)
	//a1 := alpha(rs[0], s0, zs[0], rs[1], s1, zs[1])

	//check(d_a, rs[0], s0, zs[0])
	//check(d_a, rs[1], s1, zs[1])

	//if err := checkEquation1(rs[0], s0, zs[0], d_a); err != nil {
	//log.Fatal(err)
	//}

	//if err := checkEquation1(rs[1], s1, zs[1], d_a); err != nil {
	//log.Fatal(err)
	//}

	//if err := checkEquation2a(a1, rs[0], s0, zs[0], rs[1], s1, zs[1], d_a); err != nil {
	//log.Fatal(err)
	//}

	//if err := checkEquation2b(a1, rs[0], s0, zs[0], rs[1], s1, zs[1], d_a); err != nil {
	//log.Fatal(err)
	//}

	//fmt.Println("key is", x)
	//fmt.Println("seckey", bitVector(d_a, 32))

	//err = verifyGauss(alphas, coefs, x)
	//if err != nil {
	//log.Fatal(err)
	//}
	/*fmt.Println("everything all right")*/

}
