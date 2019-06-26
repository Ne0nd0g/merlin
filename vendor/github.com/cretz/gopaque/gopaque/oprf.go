package gopaque

import (
	"go.dedis.ch/kyber"
)

// OPRFUserStep1 is executed on the user side and builds values to pass to
// server from the given x (usually a password).
func OPRFUserStep1(crypto Crypto, x []byte) (r kyber.Scalar, alpha kyber.Point) {
	// r = random
	r = crypto.Scalar().Pick(crypto.RandomStream())
	// alpha = cyclic-group-hash(x)^r
	alpha = crypto.HashToPoint(x)
	alpha.Mul(r, alpha)
	return
}

// OPRFServerStep2 is executed on the server side with alpha from user step 1
// and a "k" value that's usually either randomly generated on registration or
// looked up on auth.
func OPRFServerStep2(crypto Crypto, alpha kyber.Point, k kyber.Scalar) (v kyber.Point, beta kyber.Point) {
	// Note: we know alpha is on the curve just by being here so we don't validate it
	// v = g^k
	v = crypto.Point().Base().Mul(k, nil)
	// beta = alpha^k
	return v, crypto.Point().Mul(k, alpha)
}

// OPRFUserStep3 is executed on the client side with the original x and r from
// user step 1. The v and beta values are from server step 2. The result is the
// PRF output that can be re-obtained deterministically going through the steps
// again. It is often used to derive keys from.
func OPRFUserStep3(crypto Crypto, x []byte, r kyber.Scalar, v kyber.Point, beta kyber.Point) (out []byte) {
	// Note: we know v and beta are on the curve just by being here so we don't validate them
	// H(x, v, beta^{1/r})
	h := crypto.Hash()
	h.Write(x)
	b, err := v.MarshalBinary()
	if err != nil {
		panic(err)
	}
	h.Write(b)
	b, err = crypto.Point().Mul(crypto.Scalar().Inv(r), beta).MarshalBinary()
	if err != nil {
		panic(err)
	}
	h.Write(b)
	return h.Sum(nil)
}
