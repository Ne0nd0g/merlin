package gopaque

import (
	"encoding"
	"io"

	"go.dedis.ch/kyber"
)

// toBytes assumes the given value should not fail to marshal.
func toBytes(s encoding.BinaryMarshaler) []byte {
	// Panic on err
	b, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func pubKey(c Crypto, priv kyber.Scalar) kyber.Point {
	return c.Point().Mul(priv, nil)
}

// readerStream is a simple utility to turn a io.Reader into a cipher.Stream.
type readerStream struct {
	io.Reader
}

// XORKeyStream implements cipher.Stream.XORKeyStream.
func (r *readerStream) XORKeyStream(dst, src []byte) {
	// Similar to the Kyber random stream...
	l := len(src)
	if len(dst) < l {
		panic("dst too short")
	}
	if _, err := io.ReadFull(r, dst[:l]); err != nil {
		panic(err)
	}
	for i := 0; i < l; i++ {
		dst[i] = src[i] ^ dst[i]
	}
}
