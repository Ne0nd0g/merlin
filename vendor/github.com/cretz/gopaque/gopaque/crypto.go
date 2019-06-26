package gopaque

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"

	"crypto/aes"
	"crypto/hmac"

	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/sign/schnorr"
	"go.dedis.ch/kyber/suites"
	"go.dedis.ch/kyber/util/key"
	"go.dedis.ch/kyber/util/random"
	"golang.org/x/crypto/hkdf"
)

// KyberSuiteDefault is the recommended default kyber.Suite impl. This uses the
// Ed25519 suite which, based on reading, should satisfy the prime-order
// requirement.
var KyberSuiteDefault = suites.MustFind("Ed25519")

// CryptoDefault is the recommended default Crypto impl.
var CryptoDefault Crypto = CryptoStandardDefault

// Crypto is the abstraction of all needed features for OPAQUE.
type Crypto interface {
	suites.Suite
	KeyGenerator
	PointHasher
	KeyDeriver
	AuthEncrypter
	Signer
}

// KeyGenerator generates keys from a given stream or reader. It shares the
// NewKey signature with go.dedis.ch/kyber/util/key.Generator.
type KeyGenerator interface {
	// NewKey creates a new key from the given stream. If the stream is nil, the
	// underlying crypto random stream is used.
	NewKey(stream cipher.Stream) kyber.Scalar

	// NewKeyFromReader creates a new key for the given reader. This simply
	// wraps a io.Reader into a cipher.Stream and calls NewKey. If the reader is
	// nil, the crypto random stream is used.
	NewKeyFromReader(r io.Reader) kyber.Scalar
}

// PointHasher provides HashToPoint to create points from the hash of messages.
type PointHasher interface {
	// HashToPoint hashes the given msg to a point.
	HashToPoint(msg []byte) kyber.Point
}

// KeyDeriver provides DeriveKey to create deterministic keys from other keys.
type KeyDeriver interface {
	// DeriveKey creates a deterministic private key for the given parent
	// private key and an "info" discriminator.
	DeriveKey(priv kyber.Scalar, info []byte) kyber.Scalar
}

// AuthEncrypter provides authenticated encryption/decryption that satisfies
// OPAQUE requirements.
type AuthEncrypter interface {
	// AuthEncrypt performs an encryption of the given plain bytes
	// authenticated with the given key. It satisfies the OPAQUE requirement
	// for "key committing" meaning it's infeasible to have the same result
	// able to be decrypted successfully by different keys.
	AuthEncrypt(priv kyber.Scalar, plain []byte) ([]byte, error)

	// AuthDecrypt decrypts what was encrypted with AuthEncrypt with the same
	// key.
	AuthDecrypt(priv kyber.Scalar, enc []byte) ([]byte, error)
}

// Signer supports signing and verification.
type Signer interface {
	// Sign signs the given msg with the given priv key.
	Sign(priv kyber.Scalar, msg []byte) ([]byte, error)

	// Verify verifies the given sig for the given msg was signed by the private
	// key for the given pub key. If verification fails, the error is non-nil.
	Verify(pub kyber.Point, msg, sig []byte) error
}

// CryptoStandardDefault is the recommended default CryptoStandard impl.
var CryptoStandardDefault = &CryptoStandard{
	Suite:      KyberSuiteDefault,
	KeyDeriver: DeriveKeyHKDF,
	Signer:     &SignerSchnorr{KyberSuiteDefault},
}

// CryptoStandard implements Crypto with a given suite + key deriver + signer
// and using basic implementations of other features.
type CryptoStandard struct {
	suites.Suite
	KeyDeriver func(c Crypto, priv kyber.Scalar, info []byte) kyber.Scalar
	Signer
}

// NewKey implements KeyGenerator.NewKey.
func (c *CryptoStandard) NewKey(stream cipher.Stream) kyber.Scalar {
	if stream == nil {
		stream = c.RandomStream()
	}
	if g, _ := c.Suite.(key.Generator); g != nil {
		return g.NewKey(stream)
	}
	return c.Scalar().Pick(stream)
}

// NewKeyFromReader implements KeyGenerator.NewKeyFromReader.
func (c *CryptoStandard) NewKeyFromReader(r io.Reader) kyber.Scalar {
	if r == nil {
		return c.NewKey(nil)
	}
	return c.NewKey(&readerStream{r})
}

// HashToPoint implements PointHasher.HashToPoint.
func (c *CryptoStandard) HashToPoint(msg []byte) kyber.Point {
	// TODO: Since functionality was removed in https://github.com/dedis/kyber/pull/352, we just copied the BLS
	// code but we need to reintroduce proper elligator or something when it's back. Note, this uses LE
	// internally.
	h := c.Hash()
	h.Write(msg)
	x := c.Scalar().SetBytes(h.Sum(nil))
	return c.Point().Mul(x, nil)
}

// DeriveKey implements KeyDeriver.DeriveKey. It just defers to the KeyDeriver
// function.
func (c *CryptoStandard) DeriveKey(priv kyber.Scalar, info []byte) kyber.Scalar {
	return c.KeyDeriver(c, priv, info)
}

// AuthEncrypt implements Crypto.AuthEncrypt.
func (c *CryptoStandard) AuthEncrypt(priv kyber.Scalar, plain []byte) ([]byte, error) {
	// TODO: can an alternative be nacl secretbox instead?
	// We need two deterministic keys for the parent key, one for AES and one for MAC
	encKey, macKey := c.DeriveKey(priv, []byte("encKey")), c.DeriveKey(priv, []byte("macKey"))
	// Encrypt first
	encBytes, err := c.aesCBCEncrypt(encKey, plain)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(c.Hash, toBytes(macKey))
	mac.Write(encBytes)
	macBytes := mac.Sum(nil)
	// Just put the MAC at the end
	return append(encBytes, macBytes...), nil
}

func (c *CryptoStandard) aesCBCEncrypt(priv kyber.Scalar, plain []byte) ([]byte, error) {
	// We need to pad w/ repeated bytes of pad amount, and if none are needed we do a whole block of it
	padAmount := byte(aes.BlockSize - (len(plain) % aes.BlockSize))
	if padAmount == 0 {
		padAmount = aes.BlockSize
	}
	padded := make([]byte, len(plain)+int(padAmount))
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = padAmount
	}
	// Just use the first 32 bytes for the key if it's more than 32
	keyBytes := toBytes(priv)
	if len(keyBytes) > 32 {
		keyBytes = keyBytes[:32]
	}
	block, err := aes.NewCipher(keyBytes[:32])
	if err != nil {
		return nil, err
	}
	// Includes IV
	enc := make([]byte, aes.BlockSize+len(padded))
	random.Bytes(enc[:aes.BlockSize], c.RandomStream())
	mode := cipher.NewCBCEncrypter(block, enc[:aes.BlockSize])
	mode.CryptBlocks(enc[aes.BlockSize:], padded)
	return enc, nil
}

// AuthDecrypt implements Crypto.AuthDecrypt.
func (c *CryptoStandard) AuthDecrypt(priv kyber.Scalar, enc []byte) ([]byte, error) {
	// Build the same two keys for AES and MAC
	encKey, macKey := c.DeriveKey(priv, []byte("encKey")), c.DeriveKey(priv, []byte("macKey"))
	macSize := c.Hash().Size()
	encBytes, macBytes := enc[:len(enc)-macSize], enc[len(enc)-macSize:]
	// First check the mac
	mac := hmac.New(c.Hash, toBytes(macKey))
	mac.Write(encBytes)
	if !hmac.Equal(mac.Sum(nil), macBytes) {
		return nil, fmt.Errorf("MAC mismatch")
	}
	// Now just decrypt
	return c.aesCBCDecrypt(encKey, encBytes)
}

func (c *CryptoStandard) aesCBCDecrypt(priv kyber.Scalar, enc []byte) ([]byte, error) {
	// IV is first block
	if len(enc) < aes.BlockSize || len(enc)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("Invalid enc size")
	}
	// Just use the first 32 bytes for the key
	// Just use the first 32 bytes for the key if it's more than 32
	keyBytes := toBytes(priv)
	if len(keyBytes) > 32 {
		keyBytes = keyBytes[:32]
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	decPadded := make([]byte, len(enc[aes.BlockSize:]))
	mode := cipher.NewCBCDecrypter(block, enc[:aes.BlockSize])
	mode.CryptBlocks(decPadded, enc[aes.BlockSize:])
	// Validate it is padded with the bytes representing the pad amount
	padAmount := decPadded[len(decPadded)-1]
	if padAmount == 0 || padAmount > aes.BlockSize {
		return nil, fmt.Errorf("Pad validation fail")
	}
	for i := 1; i <= int(padAmount); i++ {
		if decPadded[len(decPadded)-i] != padAmount {
			return nil, fmt.Errorf("Pad validation fail")
		}
	}
	return decPadded[:len(decPadded)-int(padAmount)], nil
}

// DeriveKeyHKDF builds a key for the given parent key and info using
// HKDF (RFC 5869). This function can be set as the CryptoStandard.KeyDeriver
// field.
func DeriveKeyHKDF(c Crypto, priv kyber.Scalar, info []byte) kyber.Scalar {
	hkdfR := hkdf.New(c.Hash, toBytes(priv), nil, info)
	return c.NewKeyFromReader(hkdfR)
}

// DeriveKeyArgon holds parameters to use for Argon-based key derivation. See
// the DeriveKey method for more information.
type DeriveKeyArgon struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

// DeriveKeyArgonDefault is the recommended DeriveKeyArgon impl.
var DeriveKeyArgonDefault = &DeriveKeyArgon{
	Time:    1,
	Memory:  64 * 1024,
	Threads: 4,
}

// DeriveKey creates a hash of info and uses that as the Argon salt value w/ the
// key's private bytes as the Argon password to deterministically derive a seed.
// That seed is then used in NewKeyFromReader.
func (d *DeriveKeyArgon) DeriveKey(c Crypto, priv kyber.Scalar, info []byte) kyber.Scalar {
	// Build a argon2 hash with the private part of the master key as the password, the hashed info
	// as the salt, and the other argon params as given. Then use that hash as the input for a key.
	// I.e. key-gen(argon2(P=priv, S=hash(info), ...))
	h := c.Hash()
	h.Write(info)
	argonHash := argon2.IDKey(toBytes(priv), h.Sum(nil), d.Time, d.Memory, d.Threads, uint32(c.ScalarLen()))
	return c.NewKeyFromReader(bytes.NewReader(argonHash))
}

// SignerSchnorr implement Signer for Schnorr signatures.
type SignerSchnorr struct {
	schnorr.Suite
}

// Sign implements Signer.Sign.
func (s *SignerSchnorr) Sign(priv kyber.Scalar, msg []byte) ([]byte, error) {
	return schnorr.Sign(s, priv, msg)
}

// Verify implements Signer.Verify.
func (s *SignerSchnorr) Verify(pub kyber.Point, msg, sig []byte) error {
	return schnorr.Verify(s, pub, msg, sig)
}
