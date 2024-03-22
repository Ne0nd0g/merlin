/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package http

import (
	// Standard
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"time"
)

// GenerateTLSCert will generate a new certificate. Nil values in the parameters are replaced with random or blank values.
// If makeRsa is set to true, the key generated is an RSA key (EC by default).
// If a nil date is passed in for notBefore and notAfter, a random date is picked in the last year.
// If a nil date is passed in for notAfter, the date is set to be 2 years after the date provided (or generated) in the notBefore parameter.
// Please ensure privkey is a proper private key. The go implementation of this value is challenging, so no type assertion can be made in the function definition.
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

// GetTLSCertificates parses PEM encoded input x.509 certificate and key file paths as a string and returns a tls object
func GetTLSCertificates(certificate string, key string) (*tls.Certificate, error) {
	var cer tls.Certificate
	var err error

	// Check if x.509 certificate file exists on disk
	_, errCrt := os.Stat(certificate)
	if errCrt != nil {
		return &cer, fmt.Errorf("there was an error importing the SSL/TLS x509 certificate:\r\n%s", errCrt.Error())
	}

	// Check if x.509 key file exists on disk
	_, errKey := os.Stat(key)
	if errKey != nil {
		return &cer, fmt.Errorf("there was an error importing the SSL/TLS x509 key:: %s", errKey.Error())
	}

	cer, err = tls.LoadX509KeyPair(certificate, key)
	if err != nil {
		return &cer, fmt.Errorf("there was an error importing the SSL/TLS x509 key pair\r\n%s", err.Error())
	}

	if len(cer.Certificate) < 1 || cer.PrivateKey == nil {
		return &cer, fmt.Errorf("unable to import certificate because the certificate structure was empty")
	}
	return &cer, nil
}

// CheckInsecureFingerprint calculates the SHA256 hash of the passed in certificate and determines if it matches the
// publicly distributed key pair from the Merlin repository. Anyone could decrypt the TLS traffic
func CheckInsecureFingerprint(certificate tls.Certificate) (bool, error) {
	// Parse into X.509 format
	x509Certificate, errX509 := x509.ParseCertificate(certificate.Certificate[0])
	if errX509 != nil {
		return false, fmt.Errorf("there was an error parsing the tls.Certificate structure into a x509.Certificate"+
			" structure:\r\n%s", errX509.Error())
	}

	// Create fingerprint
	S256 := sha256.Sum256(x509Certificate.Raw)
	sha256Fingerprint := hex.EncodeToString(S256[:])

	// merlinCRT is the string representation of the SHA1 fingerprint for the public x.509 certificate distributed with Merlin
	merlinCRT := "4af9224c77821bc8a46503cfc2764b94b1fc8aa2521afc627e835f0b3c449f50"

	// Check to see if the Public Key SHA1 finger print matches the certificate distributed with Merlin for testing
	if merlinCRT == sha256Fingerprint {
		return true, nil
	}
	return false, nil
}

// getPublicKey takes in a private key, and provides the public key from it.
// https://golang.org/src/crypto/tls/generate_cert.go
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
