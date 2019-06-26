package gopaque

import (
	"bytes"
	"crypto/hmac"
	"fmt"

	"go.dedis.ch/kyber"
)

// KeyExchange describes a 2-step or 3-step key exchange. Although
// implementations can be used manually, they can also be used embedded into
// OPAQUE authentication via NewUserAuth and NewServerAuth. Exchanges that are
// only 2-step can return nil from UserKeyExchange3, otherwise the exchange is
// considered 3-step.
//
// While implementers will implement all methods, callers should only call the
// User* or Server* methods depending on which side they are on. The key
// exchange should be created for each use and never reused.
type KeyExchange interface {
	// UserKeyExchange1 runs on the user side and returns the first key exchange
	// value to send to server (or nil if there is none).
	UserKeyExchange1() (Marshaler, error)

	// ServerKeyExchange2 runs on the server side and is given both the result
	// of UserKeyExchange1 (if any) and the server registration info for the
	// user. It returns the value to send back to the user (or nil if there is
	// none).
	ServerKeyExchange2(ke1 Marshaler, info *KeyExchangeInfo) (Marshaler, error)

	// UserKeyExchange3 runs on the user side and is given both the result of
	// ServerKeyExchange2 (if any) and the decoded user info. It returns the
	// value sent back to the server. If the result is nil, this is only a
	// 2-message key exchange instead of a 3-message one and no more steps are
	// done.
	UserKeyExchange3(ke2 Marshaler, info *KeyExchangeInfo) (Marshaler, error)

	// ServerKeyExchange4 runs on the server side and is given the result of
	// UserKeyExchange3. It is not called if there was no result from
	// UserKeyExchange3.
	ServerKeyExchange4(ke3 Marshaler) error

	// NewKeyExchangeMessage just instantiates the message instance for the
	// result of the given step number (1-3).
	NewKeyExchangeMessage(step int) (Marshaler, error)
}

// KeyExchangeInfo is the info given from the OPAQUE process.
type KeyExchangeInfo struct {
	UserID         []byte
	MyPrivateKey   kyber.Scalar
	TheirPublicKey kyber.Point
}

// KeyExchangeSigma is a KeyExchange implementation using the 3-step SIGMA-I
// protocol as mentioned in the OPAQUE RFC.
type KeyExchangeSigma struct {
	// Info is the OPAQUE info given during either ServerKeyExchange2 or
	// UserKeyExchange3.
	Info *KeyExchangeInfo
	// SharedSecret is the Diffie-Hellman secret derived from this side's
	// ephemeral private key and the other side's ephemeral public key. It is
	// set during either ServerKeyExchange2 or UserKeyExchange3.
	SharedSecret kyber.Point

	crypto               Crypto
	myExchangePrivateKey kyber.Scalar
	myExchangePublicKey  kyber.Point
	// Server side only, user side doesn't need them across steps
	theirExchangePublicKey kyber.Point
}

// NewKeyExchangeSigma creates the SIGMA KeyExchange with the given crypto.
func NewKeyExchangeSigma(crypto Crypto) *KeyExchangeSigma { return &KeyExchangeSigma{crypto: crypto} }

// KeyExchangeSigmaMsg1 is the first exchange message sent from the user to the
// server. It implements Marshaler and is exposed only for debugging.
type KeyExchangeSigmaMsg1 struct {
	UserExchangePublicKey kyber.Point
}

// ToBytes implements Marshaler.ToBytes.
func (k *KeyExchangeSigmaMsg1) ToBytes() ([]byte, error) {
	b := newBuf(nil)
	err := b.WritePoint(k.UserExchangePublicKey)
	return b.Bytes(), err
}

// FromBytes implements Marshaler.FromBytes.
func (k *KeyExchangeSigmaMsg1) FromBytes(c Crypto, data []byte) (err error) {
	b := newBuf(data)
	k.UserExchangePublicKey, err = b.ReadPoint(c)
	return b.AssertUnmarshalNoMoreDataIfNotErr(err)
}

// UserKeyExchange1 implements KeyExchange.UserKeyExchange1.
func (k *KeyExchangeSigma) UserKeyExchange1() (Marshaler, error) {
	// KE1: g^x
	if err := k.generateExchangeKeyPair(); err != nil {
		return nil, err
	}
	return &KeyExchangeSigmaMsg1{UserExchangePublicKey: k.myExchangePublicKey}, nil
}

// KeyExchangeSigmaMsg2 is the second exchange message sent from the server to
// the server. It implements Marshaler and is exposed only for debugging.
type KeyExchangeSigmaMsg2 struct {
	ServerExchangePublicKey kyber.Point
	ServerExchangeSig       []byte
	ServerExchangeMac       []byte
}

// ToBytes implements Marshaler.ToBytes.
func (k *KeyExchangeSigmaMsg2) ToBytes() ([]byte, error) {
	b := newBuf(nil)
	err := b.WritePoint(k.ServerExchangePublicKey)
	err = b.WriteVarBytesIfNotErr(err, k.ServerExchangeSig, k.ServerExchangeMac)
	return b.Bytes(), err
}

// FromBytes implements Marshaler.FromBytes.
func (k *KeyExchangeSigmaMsg2) FromBytes(c Crypto, data []byte) (err error) {
	b := newBuf(data)
	k.ServerExchangePublicKey, err = b.ReadPoint(c)
	k.ServerExchangeSig, err = b.ReadVarBytesIfNotErr(err)
	k.ServerExchangeMac, err = b.ReadVarBytesIfNotErr(err)
	return b.AssertUnmarshalNoMoreDataIfNotErr(err)
}

// ServerKeyExchange2 implements KeyExchange.ServerKeyExchange2.
func (k *KeyExchangeSigma) ServerKeyExchange2(ke1 Marshaler, info *KeyExchangeInfo) (Marshaler, error) {
	if ke1 == nil {
		return nil, fmt.Errorf("Missing ke1")
	}
	msg1 := ke1.(*KeyExchangeSigmaMsg1)
	// KE2: g^y
	if err := k.generateExchangeKeyPair(); err != nil {
		return nil, err
	}
	msg2 := &KeyExchangeSigmaMsg2{ServerExchangePublicKey: k.myExchangePublicKey}
	// Set some local values
	k.Info = info
	k.SharedSecret = k.sharedSecret(msg1.UserExchangePublicKey)
	k.theirExchangePublicKey = msg1.UserExchangePublicKey
	// KE2: Sig(PrivS; g^x, g^y)
	hashToSign := k.createExchangeHashToSign(msg1.UserExchangePublicKey, k.myExchangePublicKey)
	var err error
	if msg2.ServerExchangeSig, err = k.crypto.Sign(info.MyPrivateKey, hashToSign); err != nil {
		return nil, err
	}
	// KE2: Mac(Km1; IdS)
	// Basically, we need to derive a mac key from the shared secret then sign
	// the server's persistent (i.e. non-exchange) public key with it.
	macKey := k.macKey(k.SharedSecret)
	msg2.ServerExchangeMac = k.createMac(macKey, pubKey(k.crypto, info.MyPrivateKey))
	return msg2, nil
}

// KeyExchangeSigmaMsg3 is the third exchange message sent from the user to the
// server. It implements Marshaler and is exposed only for debugging.
type KeyExchangeSigmaMsg3 struct {
	UserExchangeSig []byte
	UserExchangeMac []byte
}

// ToBytes implements Marshaler.ToBytes.
func (k *KeyExchangeSigmaMsg3) ToBytes() ([]byte, error) {
	b := newBuf(nil)
	b.WriteVarBytes(k.UserExchangeSig, k.UserExchangeMac)
	return b.Bytes(), nil
}

// FromBytes implements Marshaler.FromBytes.
func (k *KeyExchangeSigmaMsg3) FromBytes(c Crypto, data []byte) (err error) {
	b := newBuf(data)
	k.UserExchangeSig, err = b.ReadVarBytes()
	k.UserExchangeMac, err = b.ReadVarBytesIfNotErr(err)
	return b.AssertUnmarshalNoMoreDataIfNotErr(err)
}

// UserKeyExchange3 implements KeyExchange.UserKeyExchange3.
func (k *KeyExchangeSigma) UserKeyExchange3(ke2 Marshaler, info *KeyExchangeInfo) (Marshaler, error) {
	if ke2 == nil {
		return nil, fmt.Errorf("Missing ke2")
	}
	msg2 := ke2.(*KeyExchangeSigmaMsg2)
	// Set some local values
	k.Info = info
	k.SharedSecret = k.sharedSecret(msg2.ServerExchangePublicKey)
	// Validate the server sig
	hashToSign := k.createExchangeHashToSign(k.myExchangePublicKey, msg2.ServerExchangePublicKey)
	if err := k.crypto.Verify(info.TheirPublicKey, hashToSign, msg2.ServerExchangeSig); err != nil {
		return nil, err
	}
	// Now validate the server mac
	macKey := k.macKey(k.SharedSecret)
	if !hmac.Equal(msg2.ServerExchangeMac, k.createMac(macKey, info.TheirPublicKey)) {
		return nil, fmt.Errorf("MAC mismatch")
	}
	// Now build the response
	msg3 := &KeyExchangeSigmaMsg3{}
	// KE3: Sig(PrivU; g^y, g^x)
	var err error
	if msg3.UserExchangeSig, err = k.crypto.Sign(info.MyPrivateKey, hashToSign); err != nil {
		return nil, err
	}
	// KE3: Mac(Km2; IdU)
	msg3.UserExchangeMac = k.createMac(macKey, pubKey(k.crypto, info.MyPrivateKey))
	return msg3, nil
}

// ServerKeyExchange4 implements KeyExchange.ServerKeyExchange4.
func (k *KeyExchangeSigma) ServerKeyExchange4(ke3 Marshaler) error {
	if ke3 == nil {
		return fmt.Errorf("Missing ke3")
	}
	msg3 := ke3.(*KeyExchangeSigmaMsg3)
	// First, validate the user sig
	hashToSign := k.createExchangeHashToSign(k.theirExchangePublicKey, k.myExchangePublicKey)
	if err := k.crypto.Verify(k.Info.TheirPublicKey, hashToSign, msg3.UserExchangeSig); err != nil {
		return err
	}
	// Now validate the server mac
	macKey := k.macKey(k.SharedSecret)
	if !hmac.Equal(msg3.UserExchangeMac, k.createMac(macKey, k.Info.TheirPublicKey)) {
		return fmt.Errorf("MAC mismatch")
	}
	return nil
}

// NewKeyExchangeMessage implements KeyExchange.NewKeyExchangeMessage.
func (k *KeyExchangeSigma) NewKeyExchangeMessage(step int) (Marshaler, error) {
	switch step {
	case 1:
		return &KeyExchangeSigmaMsg1{}, nil
	case 2:
		return &KeyExchangeSigmaMsg2{}, nil
	case 3:
		return &KeyExchangeSigmaMsg3{}, nil
	default:
		return nil, fmt.Errorf("Invalid step")
	}
}

func (k *KeyExchangeSigma) generateExchangeKeyPair() error {
	if k.myExchangePrivateKey != nil {
		return fmt.Errorf("Private key already set, has this already run?")
	}
	k.myExchangePrivateKey = k.crypto.NewKey(nil)
	k.myExchangePublicKey = pubKey(k.crypto, k.myExchangePrivateKey)
	return nil
}

func (k *KeyExchangeSigma) sharedSecret(theirPub kyber.Point) kyber.Point {
	return k.crypto.Point().Mul(k.myExchangePrivateKey, theirPub)
}

func (k *KeyExchangeSigma) macKey(sharedSecret kyber.Point) kyber.Scalar {
	// We create the parent scalar from point then derive
	sharedSecretKey := k.crypto.NewKeyFromReader(bytes.NewReader(toBytes(sharedSecret)))
	return k.crypto.DeriveKey(sharedSecretKey, []byte("sigma-mac"))
}

func (k *KeyExchangeSigma) createMac(macKey kyber.Scalar, v kyber.Point) []byte {
	h := hmac.New(k.crypto.Hash, toBytes(macKey))
	h.Write(toBytes(v))
	return h.Sum(nil)
}

func (k *KeyExchangeSigma) createExchangeHashToSign(userPub, serverPub kyber.Point) []byte {
	h := k.crypto.Hash()
	h.Write(toBytes(userPub))
	h.Write(toBytes(serverPub))
	return h.Sum(nil)
}
