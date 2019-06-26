package gopaque

import (
	"bytes"

	"go.dedis.ch/kyber"
)

// UserRegister is the user-side session for registration with a server. This
// should be created for each server registration and never reused. Once
// created via NewUserRegister, Init can be called with a password that will
// return a value that can be sent to the server. The value that the server
// returns can then be used for Complete. The resulting value from Complete is
// then passed back to the server to complete registration.
type UserRegister struct {
	crypto     Crypto
	userID     []byte
	privateKey kyber.Scalar
	password   []byte
	r          kyber.Scalar
}

// NewUserRegister creates a registration session for the given userID. If
// privateKey is nil (recommended), it is generated. A key should never be
// reused on different registrations.
func NewUserRegister(crypto Crypto, userID []byte, privateKey kyber.Scalar) *UserRegister {
	if privateKey == nil {
		privateKey = crypto.NewKey(nil)
	}
	return &UserRegister{crypto: crypto, userID: userID, privateKey: privateKey}
}

// PrivateKey gives the key used during registration. This is often generated on
// NewUserRegister. It is rarely needed because it comes back on authenticate as
// well.
func (u *UserRegister) PrivateKey() kyber.Scalar { return u.privateKey }

// UserRegisterInit is the set of data to pass to the server after calling
// UserRegister.Init. It implements Marshaler.
type UserRegisterInit struct {
	UserID []byte
	Alpha  kyber.Point
}

// ToBytes implements Marshaler.ToBytes.
func (u *UserRegisterInit) ToBytes() ([]byte, error) {
	b := newBuf(nil)
	b.WriteVarBytes(u.UserID)
	err := b.WritePoint(u.Alpha)
	return b.Bytes(), err
}

// FromBytes implements Marshaler.FromBytes. This can return
// ErrUnmarshalMoreData if the data is too big.
func (u *UserRegisterInit) FromBytes(c Crypto, data []byte) (err error) {
	b := newBuf(data)
	u.UserID, err = b.ReadVarBytes()
	u.Alpha, err = b.ReadPointIfNotErr(c, err)
	return b.AssertUnmarshalNoMoreDataIfNotErr(err)
}

// Init creates an init message for the password.
func (u *UserRegister) Init(password []byte) *UserRegisterInit {
	// Set user password
	u.password = password
	// Start OPRF
	init := &UserRegisterInit{UserID: u.userID}
	u.r, init.Alpha = OPRFUserStep1(u.crypto, password)
	return init
}

// UserRegisterComplete is the set of data to pass to the server after calling
// Complete. It implements Marshaler.
type UserRegisterComplete struct {
	UserPublicKey kyber.Point
	EnvU          []byte
}

// ToBytes implements Marshaler.ToBytes.
func (u *UserRegisterComplete) ToBytes() ([]byte, error) {
	b := newBuf(nil)
	err := b.WritePoint(u.UserPublicKey)
	err = b.WriteVarBytesIfNotErr(err, u.EnvU)
	return b.Bytes(), err
}

// FromBytes implements Marshaler.FromBytes. This can return
// ErrUnmarshalMoreData if the data is too big.
func (u *UserRegisterComplete) FromBytes(c Crypto, data []byte) (err error) {
	b := newBuf(data)
	u.UserPublicKey, err = b.ReadPoint(c)
	u.EnvU, err = b.ReadVarBytesIfNotErr(err)
	return b.AssertUnmarshalNoMoreDataIfNotErr(err)
}

// Complete is called after receiving the server init results. The result of
// this call should be passed back to the server.
func (u *UserRegister) Complete(s *ServerRegisterInit) *UserRegisterComplete {
	if len(u.password) == 0 {
		panic("No password, was init run?")
	}
	// Finish up OPRF
	rwdU := OPRFUserStep3(u.crypto, u.password, u.r, s.V, s.Beta)
	// Generate a key pair from rwdU seed
	authEncKey := u.crypto.NewKeyFromReader(bytes.NewReader(rwdU))
	// Generate the envelope by encrypting my pair and server pub w/ the OPRF result as the key
	plain := append(toBytes(u.privateKey), toBytes(s.ServerPublicKey)...)
	envU, err := u.crypto.AuthEncrypt(authEncKey, plain)
	if err != nil {
		panic(err)
	}
	return &UserRegisterComplete{UserPublicKey: pubKey(u.crypto, u.privateKey), EnvU: envU}
}

// ServerRegister is the server-side session for registration with a user. This
// should be created for each user registration and never reused. Once created
// via NewServerRegister, Init should be called with the value from the user
// side and then the result should be passed back to the user. The user-side's
// next value should be passed to Complete and the results of Complete should
// be stored by the server.
type ServerRegister struct {
	crypto     Crypto
	privateKey kyber.Scalar
	kU         kyber.Scalar
	userID     []byte
}

// NewServerRegister creates a ServerRegister with the given key. The key can
// be the same as used for other registrations.
func NewServerRegister(crypto Crypto, privateKey kyber.Scalar) *ServerRegister {
	return &ServerRegister{
		crypto:     crypto,
		privateKey: privateKey,
		kU:         crypto.Scalar().Pick(crypto.RandomStream()),
	}
}

// ServerRegisterInit is the result of Init to be passed to the user. It
// implements Marshaler.
type ServerRegisterInit struct {
	ServerPublicKey kyber.Point
	V               kyber.Point
	Beta            kyber.Point
}

// ToBytes implements Marshaler.ToBytes.
func (s *ServerRegisterInit) ToBytes() ([]byte, error) {
	b := newBuf(nil)
	err := b.WritePoint(s.ServerPublicKey, s.V, s.Beta)
	return b.Bytes(), err
}

// FromBytes implements Marshaler.FromBytes. This can return
// ErrUnmarshalMoreData if the data is too big.
func (s *ServerRegisterInit) FromBytes(c Crypto, data []byte) (err error) {
	b := newBuf(data)
	s.ServerPublicKey, err = b.ReadPoint(c)
	s.V, err = b.ReadPointIfNotErr(c, err)
	s.Beta, err = b.ReadPointIfNotErr(c, err)
	return b.AssertUnmarshalNoMoreDataIfNotErr(err)
}

// Init is called with the first data received from the user side. The response
// should be sent back to the user.
func (s *ServerRegister) Init(u *UserRegisterInit) *ServerRegisterInit {
	// Store the user ID
	s.userID = u.UserID
	// Do server-side OPRF step
	i := &ServerRegisterInit{ServerPublicKey: pubKey(s.crypto, s.privateKey)}
	i.V, i.Beta = OPRFServerStep2(s.crypto, u.Alpha, s.kU)
	return i
}

// ServerRegisterComplete is the completed set of data that should be stored by
// the server on successful registration.
type ServerRegisterComplete struct {
	UserID []byte
	// Same as given originally, can be global
	ServerPrivateKey kyber.Scalar
	UserPublicKey    kyber.Point
	EnvU             []byte
	KU               kyber.Scalar
}

// Complete takes the last info from the user and returns a st of data that
// must be stored by the server.
func (s *ServerRegister) Complete(u *UserRegisterComplete) *ServerRegisterComplete {
	// Just return the stuff as complete
	return &ServerRegisterComplete{
		UserID:           s.userID,
		ServerPrivateKey: s.privateKey,
		UserPublicKey:    u.UserPublicKey,
		EnvU:             u.EnvU,
		KU:               s.kU,
	}
}
