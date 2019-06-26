// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2019  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package core

import (
	// Standard
	"bytes"
	"crypto/rsa"
	"encoding/gob"
	"fmt"
	"math/rand"
	"os"
	"time"

	// 3rd Party
	"gopkg.in/square/go-jose.v2"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// Debug puts Merlin into debug mode and displays debug messages
var Debug = false

// Verbose puts Merlin into verbose mode and displays verbose messages
var Verbose = false

// CurrentDir is the current directory where Merlin was executed from
var CurrentDir, _ = os.Getwd()
var src = rand.NewSource(time.Now().UnixNano())

// Constants
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// RandStringBytesMaskImprSrc generates and returns a random string of n characters long
func RandStringBytesMaskImprSrc(n int) string {
	// http://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-golang
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}

// DecryptJWE takes provided JWE string and decrypts it using the per-agent key
func DecryptJWE(jweString string, key []byte) (messages.Base, error) {
	var m messages.Base

	// Parse JWE string back into JSONWebEncryption
	jwe, errObject := jose.ParseEncrypted(jweString)
	if errObject != nil {
		return m, fmt.Errorf("there was an error parseing the JWE string into a JSONWebEncryption object:\r\n%s", errObject)
	}

	// Decrypt the JWE
	jweMessage, errDecrypt := jwe.Decrypt(key)
	if errDecrypt != nil {
		return m, fmt.Errorf("there was an error decrypting the JWE string:\r\n%s", errDecrypt.Error())
	}

	// Decode the JWE payload into a messages.Base struct
	errDecode := gob.NewDecoder(bytes.NewReader(jweMessage)).Decode(&m)
	if errDecode != nil {
		return m, fmt.Errorf("there was an error decoding JWE payload message sent by an agent:\r\n%s", errDecode.Error())
	}

	return m, nil
}

// GetJWESymetric takes an input, typically a gob encoded messages.Base, and returns a compact serialized JWE using the
// provided input key
func GetJWESymetric(data []byte, key []byte) (string, error) {
	//   Keys used with AES GCM must follow the constraints in Section 8.3 of
	//   [NIST.800-38D], which states: "The total number of invocations of the
	//   authenticated encryption function shall not exceed 2^32, including
	//   all IV lengths and all instances of the authenticated encryption
	//   function with the given key".  In accordance with this rule, AES GCM
	//   MUST NOT be used with the same key value more than 2^32 times. == 4294967296
	//   TODO ensure no more than 4294967295 JWE's are created using the same key
	encrypter, encErr := jose.NewEncrypter(jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.PBES2_HS512_A256KW, // Creates a per message key encrypted with the passed in key
			//Algorithm: jose.DIRECT, // Doesn't create a per message key
			PBES2Count: 500000,
			Key:        key},
		nil)
	if encErr != nil {
		return "", fmt.Errorf("there was an error creating the JWE encryptor:\r\n%s", encErr)
	}
	jwe, errJWE := encrypter.Encrypt(data)
	if errJWE != nil {
		return "", fmt.Errorf("there was an error encrypting the Authentication JSON object to a JWE object:\r\n%s", errJWE.Error())
	}

	serialized, errSerialized := jwe.CompactSerialize()
	if errSerialized != nil {
		return "", fmt.Errorf("there was an error serializing the JWE in compact format:\r\n%s", errSerialized.Error())
	}

	// Parse it to make sure there were no errors serializing it
	_, errJWE = jose.ParseEncrypted(serialized)
	if errJWE != nil {
		return "", fmt.Errorf("there was an error parsing the encrypted JWE:\r\n%s", errJWE.Error())
	}

	return serialized, nil
}

// GetJWEAsymetric takes an input, typically a gob encoded messages.Base, and returns a compact serialized JWE using the
// provided input RSA public key
func GetJWEAsymetric(data []byte, key *rsa.PublicKey) (string, error) {
	// TODO change key algorithm to ECDH
	encrypter, encErr := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.RSA_OAEP, Key: key}, nil)
	if encErr != nil {
		return "", fmt.Errorf("there was an error creating the agent encryptor:\r\n%s", encErr)
	}
	jwe, errJWE := encrypter.Encrypt(data)
	if errJWE != nil {
		return "", fmt.Errorf("there was an error encrypting the data into a JWE object:\r\n%s", errJWE.Error())
	}

	serialized, errSerialized := jwe.CompactSerialize()
	if errSerialized != nil {
		return "", fmt.Errorf("there was an error serializing the JWE in compact format:\r\n%s", errSerialized.Error())
	}

	// Parse it to make sure there were no errors serializing it
	_, errJWE = jose.ParseEncrypted(serialized)
	if errJWE != nil {
		return "", fmt.Errorf("there was an error parsing the encrypted JWE:\r\n%s", errJWE.Error())
	}

	return serialized, nil
}
