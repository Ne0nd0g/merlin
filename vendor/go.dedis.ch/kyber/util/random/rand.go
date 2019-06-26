// Package random provides facilities for generating
// random or pseudorandom cryptographic objects.
package random

import (
	"crypto/cipher"
	"crypto/rand"
	"math/big"
)

// Bits chooses a uniform random BigInt with a given maximum BitLen.
// If 'exact' is true, choose a BigInt with _exactly_ that BitLen, not less
func Bits(bitlen uint, exact bool, rand cipher.Stream) []byte {
	b := make([]byte, (bitlen+7)/8)
	rand.XORKeyStream(b, b)
	highbits := bitlen & 7
	if highbits != 0 {
		b[0] &= ^(0xff << highbits)
	}
	if exact {
		if highbits != 0 {
			b[0] |= 1 << (highbits - 1)
		} else {
			b[0] |= 0x80
		}
	}
	return b
}

// Int chooses a uniform random big.Int less than a given modulus
func Int(mod *big.Int, rand cipher.Stream) *big.Int {
	bitlen := uint(mod.BitLen())
	i := new(big.Int)
	for {
		i.SetBytes(Bits(bitlen, false, rand))
		if i.Sign() > 0 && i.Cmp(mod) < 0 {
			return i
		}
	}
}

// Bytes fills a slice with random bytes from rand.
func Bytes(b []byte, rand cipher.Stream) {
	rand.XORKeyStream(b, b)
}

type randstream struct {
}

func (r *randstream) XORKeyStream(dst, src []byte) {
	// This function works only on local data, so it is
	// safe against race conditions, as long as crypto/rand
	// is as well. (It is.)

	l := len(dst)
	if len(src) != l {
		panic("XORKeyStream: mismatched buffer lengths")
	}

	buf := make([]byte, l)
	n, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	if n < len(buf) {
		panic("short read on infinite random stream!?")
	}

	for i := 0; i < l; i++ {
		dst[i] = src[i] ^ buf[i]
	}
}

// New returns a new cipher.Stream that gets random data from Go's crypto/rand package.
// The resulting cipher.Stream can be used in multiple threads.
func New() cipher.Stream {
	return &randstream{}
}
