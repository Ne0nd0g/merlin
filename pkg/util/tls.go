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

package util

import (
	// Standard
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

/*
GenerateTLSCert will generate a new certificate. Nil values in the parameters are replaced with random or blank values.

If makeRsa is set to true, the key generated is an RSA key (EC by default).

If a nil date is passed in for notBefore and notAfter, a random date is picked in the last year.

If a nil date is passed in for notAfter, the date is set to be 2 years after the date provided (or generated) in the notBefore parameter.

Please ensure privkey is a proper private key. The go implementation of this value is challenging, so no type assertion can be made in the function definition.
*/
func GenerateTLSCert(serial *big.Int, subject *pkix.Name, dnsNames []string, notBefore, notAfter *time.Time, privKey crypto.PrivateKey, makeRsa bool) (*tls.Certificate, error) {
	//https://golang.org/src/crypto/tls/generate_cert.go taken from here mostly
	var err error

	if serial == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128) //128 bits tops
		serial, err = rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, err
		}
	}

	if subject == nil { //pointers make it easier to compare to nils
		subject = &pkix.Name{} //todo: generate random subject attributes?
	}

	//todo: generate random names?

	if notBefore == nil {

		randDay, err := rand.Int(rand.Reader, big.NewInt(360)) //not 365, playing it safe... time and computers are hard
		if err != nil {
			return nil, err
		}

		b4 := time.Now().AddDate(0, 0, -1*int(randDay.Int64())) //random date sometime in the last year
		notBefore = &b4
	}

	if notAfter == nil {
		aft := notBefore.AddDate(2, 0, 0) //2 years after the notbefore date
		notAfter = &aft
	}

	tpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               *subject,
		DNSNames:              dnsNames,
		NotBefore:             *notBefore,
		NotAfter:              *notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if privKey == nil {
		if makeRsa {
			privKey, err = rsa.GenerateKey(rand.Reader, 4096)
			if err != nil {
				return nil, err
			}
		} else {
			privKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader) //maybe check to see if P384 is the right choice (would want to be the most common choice for ec curves)
			if err != nil {
				return nil, err
			}
		}
	}

	crtBytes, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, getPublicKey(privKey), privKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{crtBytes},
		PrivateKey:  privKey,
	}, nil
}

//getPublicKey takes in a private key, and provides the public key from it.
//https://golang.org/src/crypto/tls/generate_cert.go
func getPublicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
