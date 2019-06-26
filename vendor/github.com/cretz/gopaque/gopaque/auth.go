package gopaque

import (
	"bytes"
	"fmt"

	"go.dedis.ch/kyber"
)

// UserAuth is the user-side authentication session for a registered user. The
// Init step gives a message that can be sent to the server and the response can
// be given to Complete to complete the authentication. Both the message sent
// from Init and received from the server are should interspersed in an existing
// key exchange. The key exchange can be embedded or external, see NewUserAuth.
//
// This should be created each auth attempt and never reused.
type UserAuth struct {
	crypto              Crypto
	userID              []byte
	embeddedKeyExchange KeyExchange
	password            []byte
	r                   kyber.Scalar
}

// NewUserAuth creates a new auth session for the given userID. The auth should
// run alongside a key exchange. If embeddedKeyExchange is nil, the key exchange
// is expected to be done by the caller with these messages embedded within.
// This means Complete will not return a message to send back to the server
// since OPAQUE only requires the two steps. If embeddedKeyExchange is not nil,
// the key exchange will be done as part of the auth here and shipped alongside
// the messages. If the key exchange is a 3-step then Complete will provide a
// message to send back to the server.
func NewUserAuth(crypto Crypto, userID []byte, embeddedKeyExchange KeyExchange) *UserAuth {
	return &UserAuth{crypto: crypto, userID: userID, embeddedKeyExchange: embeddedKeyExchange}
}

// UserAuthInit is the set of data to pass to the server after calling
// UserAuth.Init. It implements Marshaler.
type UserAuthInit struct {
	UserID []byte

	Alpha                       kyber.Point
	EmbeddedKeyExchangeMessage1 []byte
}

// ToBytes implements Marshaler.ToBytes.
func (u *UserAuthInit) ToBytes() ([]byte, error) {
	b := newBuf(nil)
	b.WriteVarBytes(u.UserID)
	err := b.WritePoint(u.Alpha)
	err = b.WriteVarBytesIfNotErr(err, u.EmbeddedKeyExchangeMessage1)
	return b.Bytes(), err
}

// FromBytes implements Marshaler.FromBytes. This can return
// ErrUnmarshalMoreData if the data is too big.
func (u *UserAuthInit) FromBytes(c Crypto, data []byte) (err error) {
	b := newBuf(data)
	u.UserID, err = b.ReadVarBytes()
	u.Alpha, err = b.ReadPointIfNotErr(c, err)
	u.EmbeddedKeyExchangeMessage1, err = b.ReadVarBytesIfNotErr(err)
	return b.AssertUnmarshalNoMoreDataIfNotErr(err)
}

// Init creates the first set of data to send to the server from the given
// password. Error is always nil if there is no embedded key exchange.
func (u *UserAuth) Init(password []byte) (*UserAuthInit, error) {
	u.password = password
	init := &UserAuthInit{UserID: u.userID}
	u.r, init.Alpha = OPRFUserStep1(u.crypto, password)
	// If there is an embedded key exchange, run its user step
	if u.embeddedKeyExchange != nil {
		if ke1, err := u.embeddedKeyExchange.UserKeyExchange1(); err != nil {
			return nil, err
		} else if init.EmbeddedKeyExchangeMessage1, err = ke1.ToBytes(); err != nil {
			return nil, err
		}
	}
	return init, nil
}

// UserAuthFinish is the completed information for use once auth is done.
type UserAuthFinish struct {
	UserPrivateKey  kyber.Scalar
	ServerPublicKey kyber.Point
}

// UserAuthComplete is sent back to the server to complete auth if needed. It
// implements Marshaler.
type UserAuthComplete struct {
	EmbeddedKeyExchangeMessage3 []byte
}

// ToBytes implements Marshaler.ToBytes.
func (u *UserAuthComplete) ToBytes() ([]byte, error) {
	b := newBuf(nil)
	b.WriteVarBytes(u.EmbeddedKeyExchangeMessage3)
	return b.Bytes(), nil
}

// FromBytes implements Marshaler.FromBytes. This can return
// ErrUnmarshalMoreData if the data is too big.
func (u *UserAuthComplete) FromBytes(c Crypto, data []byte) (err error) {
	b := newBuf(data)
	u.EmbeddedKeyExchangeMessage3, err = b.ReadVarBytes()
	return b.AssertUnmarshalNoMoreDataIfNotErr(err)
}

// Complete takes the server's complete information and decrypts it and returns
// the user auth information as UserAuthFinish. If there is an embedded key
// exchange and it's a 3-step one (meaning KeyExchange.UserKeyExchange3 returns
// a value), then a UserAuthComplete record is returned to send back to the
// server for completion. Otherwise, the UserAuthComplete is nil and there are
// no more steps. If there is no embedded key exchange, the external key
// exchange performed by the caller may do more after this.
func (u *UserAuth) Complete(s *ServerAuthComplete) (*UserAuthFinish, *UserAuthComplete, error) {
	// Decode and build finish info
	rwdU := OPRFUserStep3(u.crypto, u.password, u.r, s.V, s.Beta)
	decKey := u.crypto.NewKeyFromReader(bytes.NewReader(rwdU))
	finish := &UserAuthFinish{UserPrivateKey: u.crypto.Scalar(), ServerPublicKey: u.crypto.Point()}
	privKeyLen := u.crypto.ScalarLen()
	if plain, err := u.crypto.AuthDecrypt(decKey, s.EnvU); err != nil {
		return nil, nil, err
	} else if err = finish.UserPrivateKey.UnmarshalBinary(plain[:privKeyLen]); err != nil {
		return nil, nil, err
	} else if err = finish.ServerPublicKey.UnmarshalBinary(plain[privKeyLen:]); err != nil {
		return nil, nil, err
	} else if !finish.ServerPublicKey.Equal(s.ServerPublicKey) {
		return nil, nil, fmt.Errorf("Server public key mismatch")
	}
	// If there is an embedded key exchange, run it
	var complete *UserAuthComplete
	if u.embeddedKeyExchange != nil {
		complete = &UserAuthComplete{}
		info := &KeyExchangeInfo{u.userID, finish.UserPrivateKey, finish.ServerPublicKey}
		if len(s.EmbeddedKeyExchangeMessage2) == 0 {
			return nil, nil, fmt.Errorf("Missing expected exchange message 2")
		} else if ke2, err := u.embeddedKeyExchange.NewKeyExchangeMessage(2); err != nil {
			return nil, nil, err
		} else if err = ke2.FromBytes(u.crypto, s.EmbeddedKeyExchangeMessage2); err != nil {
			return nil, nil, err
		} else if ke3, err := u.embeddedKeyExchange.UserKeyExchange3(ke2, info); err != nil {
			return nil, nil, err
		} else if ke3 == nil {
			// This is only a 2-step exchange
			complete = nil
		} else if complete.EmbeddedKeyExchangeMessage3, err = ke3.ToBytes(); err != nil {
			return nil, nil, err
		}
	}
	return finish, complete, nil
}

// ServerAuth is the server-side authentication session for a registered user.
// The Complete step takes a user message and gives a message that can be sent
// back. This should be interspersed with a key exchange which can be embedded
// or external, see NewServerAuth. If key exchange is embedded and there is a
// UserAuthComplete, it should be passed to Finish to complete with the embedded
// key exchange. Otherwise, Finish is not necessary.
//
// This should be created each auth attempt and never reused.
type ServerAuth struct {
	crypto              Crypto
	embeddedKeyExchange KeyExchange
}

// NewServerAuth creates a new auth session for a user. The auth should
// run alongside a key exchange. If embeddedKeyExchange is nil, the key exchange
// is expected to be done by the caller with these messages embedded within.
// If there is an embeddedKeyExchange and it is a 3-step one (meaning there is
// a UserAuthComplete given back) then Finish should be called. Otherwise,
// Finish is not necessary.
func NewServerAuth(crypto Crypto, embeddedKeyExchange KeyExchange) *ServerAuth {
	return &ServerAuth{crypto: crypto, embeddedKeyExchange: embeddedKeyExchange}
}

// ServerAuthComplete is the resulting info from ServerAuth to send back to the
// user. It implements Marshaler.
type ServerAuthComplete struct {
	ServerPublicKey kyber.Point

	EnvU                        []byte
	V                           kyber.Point
	Beta                        kyber.Point
	EmbeddedKeyExchangeMessage2 []byte
}

// ToBytes implements Marshaler.ToBytes.
func (s *ServerAuthComplete) ToBytes() ([]byte, error) {
	b := newBuf(nil)
	err := b.WritePoint(s.ServerPublicKey)
	err = b.WriteVarBytesIfNotErr(err, s.EnvU)
	err = b.WritePointIfNotErr(err, s.V, s.Beta)
	err = b.WriteVarBytesIfNotErr(err, s.EmbeddedKeyExchangeMessage2)
	return b.Bytes(), err
}

// FromBytes implements Marshaler.FromBytes. This can return
// ErrUnmarshalMoreData if the data is too big.
func (s *ServerAuthComplete) FromBytes(c Crypto, data []byte) (err error) {
	b := newBuf(data)
	s.ServerPublicKey, err = b.ReadPoint(c)
	s.EnvU, err = b.ReadVarBytesIfNotErr(err)
	s.V, err = b.ReadPointIfNotErr(c, err)
	s.Beta, err = b.ReadPointIfNotErr(c, err)
	s.EmbeddedKeyExchangeMessage2, err = b.ReadVarBytesIfNotErr(err)
	return b.AssertUnmarshalNoMoreDataIfNotErr(err)
}

// Complete combines the received UserAuthInit information with the stored
// ServerRegisterComplete information to produce the authentication info to
// give back to the user. If there is no embedded key exchange or it is only a
// 2-step exchange, this is the last call required. Otherwise, Finish must be
// called to complete the auth. If there is no embedded key exchange, error is
// always nil.
func (s *ServerAuth) Complete(u *UserAuthInit, regInfo *ServerRegisterComplete) (*ServerAuthComplete, error) {
	if !bytes.Equal(u.UserID, regInfo.UserID) {
		panic("Mismatched user IDs")
	}
	complete := &ServerAuthComplete{
		ServerPublicKey: pubKey(s.crypto, regInfo.ServerPrivateKey),
		EnvU:            regInfo.EnvU,
	}
	complete.V, complete.Beta = OPRFServerStep2(s.crypto, u.Alpha, regInfo.KU)
	// If there is an embedded key exchange, run it
	if s.embeddedKeyExchange != nil {
		info := &KeyExchangeInfo{u.UserID, regInfo.ServerPrivateKey, regInfo.UserPublicKey}
		if len(u.EmbeddedKeyExchangeMessage1) == 0 {
			return nil, fmt.Errorf("Missing expected exchange message 1")
		} else if ke1, err := s.embeddedKeyExchange.NewKeyExchangeMessage(1); err != nil {
			return nil, err
		} else if err = ke1.FromBytes(s.crypto, u.EmbeddedKeyExchangeMessage1); err != nil {
			return nil, err
		} else if ke2, err := s.embeddedKeyExchange.ServerKeyExchange2(ke1, info); err != nil {
			return nil, err
		} else if complete.EmbeddedKeyExchangeMessage2, err = ke2.ToBytes(); err != nil {
			return nil, err
		}
	}
	return complete, nil
}

// Finish simply validates the given user auth complete. This can only be called
// if there is an embedded key exchange and it is a 3-step exchange. Otherwise,
// Complete is the last OPAQUE step and the caller can use it in an external
// key exchange.
func (s *ServerAuth) Finish(u *UserAuthComplete) error {
	if s.embeddedKeyExchange == nil {
		return fmt.Errorf("Finish can only be run as last step of embedded key exchange")
	} else if u == nil || len(u.EmbeddedKeyExchangeMessage3) == 0 {
		return fmt.Errorf("Expected embedded key exchange message, got nothing")
	} else if ke3, err := s.embeddedKeyExchange.NewKeyExchangeMessage(3); err != nil {
		return err
	} else if err = ke3.FromBytes(s.crypto, u.EmbeddedKeyExchangeMessage3); err != nil {
		return err
	} else {
		return s.embeddedKeyExchange.ServerKeyExchange4(ke3)
	}
}
