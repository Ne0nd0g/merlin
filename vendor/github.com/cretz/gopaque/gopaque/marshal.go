package gopaque

import (
	"bytes"
	"encoding/binary"
	"io"

	"go.dedis.ch/kyber"
)

// Marshaler is implemented by any message that can be marshaled to/from bytes.
type Marshaler interface {
	// ToBytes converts this to a byte slice. If successful should always have
	// at least one byte.
	ToBytes() ([]byte, error)

	// FromBytes populates this from a byte slice. This can return
	// ErrUnmarshalMoreData if the data is too big.
	FromBytes(Crypto, []byte) error
}

// ErrUnmarshalMoreData is when there is more data after unmarshalling.
type ErrUnmarshalMoreData struct {
	// Left is the number of bytes not handled.
	Left int
}

func (e *ErrUnmarshalMoreData) Error() string { return "Expected EOF, still more data" }

type buf struct {
	*bytes.Buffer
}

func newBuf(b []byte) *buf { return &buf{bytes.NewBuffer(b)} }

func (b *buf) AssertUnmarshalNoMoreDataIfNotErr(err error) error {
	if err == nil && b.Len() > 0 {
		err = &ErrUnmarshalMoreData{b.Len()}
	}
	return err
}

func (b *buf) ReadPoint(c Crypto) (kyber.Point, error) {
	p := c.Point()
	_, err := p.UnmarshalFrom(b)
	return p, err
}

func (b *buf) ReadPointIfNotErr(c Crypto, err error) (kyber.Point, error) {
	if err != nil {
		return nil, err
	}
	return b.ReadPoint(c)
}

func (b *buf) WritePoint(points ...kyber.Point) error {
	for _, p := range points {
		if _, err := p.MarshalTo(b); err != nil {
			return err
		}
	}
	return nil
}

func (b *buf) WritePointIfNotErr(err error, points ...kyber.Point) error {
	if err == nil {
		err = b.WritePoint(points...)
	}
	return err
}

func (b *buf) ReadVarBytes() ([]byte, error) {
	var l uint32
	binary.Read(b, binary.BigEndian, &l)
	if b.Len() < int(l) {
		return nil, io.EOF
	}
	byts := make([]byte, l)
	b.Read(byts)
	return byts, nil
}

func (b *buf) ReadVarBytesIfNotErr(err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return b.ReadVarBytes()
}

func (b *buf) WriteVarBytes(slices ...[]byte) {
	for _, s := range slices {
		binary.Write(b, binary.BigEndian, uint32(len(s)))
		b.Write(s)
	}
}

func (b *buf) WriteVarBytesIfNotErr(err error, slices ...[]byte) error {
	if err == nil {
		b.WriteVarBytes(slices...)
	}
	return err
}
