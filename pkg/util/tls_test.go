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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"
	"time"
)

//test files for the exported functions in the 'util' package
// TestTLSCertGeneration tests certificate generation from the util package
func TestTLSCertGeneration(t *testing.T) {
	// Setup
	//serial
	serial := big.NewInt(1337)
	//subject
	cnString := "It's in that place where I put that thing that time"
	subj := pkix.Name{
		CommonName: cnString,
	}
	//dnsNames
	dnsName := "HackThePlanet.org"
	dnsNames := []string{dnsName}
	//time (before and after)
	notBefore := time.Now().AddDate(0, 0, -5) // 5 days ago
	notAfter := time.Now().AddDate(13, 3, 7)  //13 years, 3 months, 7 days
	//privKey
	ecpk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal("Couldn't generate EC key", err)
	}
	pk := crypto.PrivateKey(ecpk)

	// Create certificate
	certSetVals, err := GenerateTLSCert(serial, &subj, dnsNames, &notBefore, &notAfter, pk, false)
	if err != nil {
		t.Fatal("Certificate generation[1] error:" + err.Error())
	}

	// Tests
	x5certSetVals, err := x509.ParseCertificate(certSetVals.Certificate[0])
	if err != nil {
		t.Fatal("Could not parse X509 certificate")
	}
	//serial
	if x5certSetVals.SerialNumber.Cmp(serial) != 0 {
		t.Error("Serial number mismatch")
	}
	//subject
	if x5certSetVals.Subject.CommonName != cnString {
		t.Error("cn mismatch in subject: \n" + x5certSetVals.Subject.CommonName + "\n should be \n" + cnString)
	}

	//dnsNames
	if len(x5certSetVals.DNSNames) < 1 || x5certSetVals.DNSNames[0] != dnsName {
		t.Error(fmt.Sprintf("dnsnames failed assignment: should be a length 1 string slice with the only "+
			"contents:\n%s\nbut is:\n%v", dnsName, x5certSetVals.DNSNames))
	}

	//times
	expectYear, expectMonth, expectDay := notBefore.Date()
	certYear, certMonth, certDay := x5certSetVals.NotBefore.Date()
	if expectYear != certYear || expectMonth != certMonth || expectDay != certDay {
		t.Error(fmt.Errorf(
			"before date invalid:\nYear:%v (expected %v)\nMonth:%v (expected %v)\nDay:%v (expected %v)",
			certYear,
			expectYear,
			certMonth,
			expectMonth,
			certDay,
			expectDay,
		))
	}
	expectYear, expectMonth, expectDay = notAfter.Date()
	certYear, certMonth, certDay = x5certSetVals.NotAfter.Date()
	if expectYear != certYear || expectMonth != certMonth || expectDay != certDay {
		t.Error(fmt.Errorf(
			"after date invalid:\nYear:%v (expected %v)\nMonth:%v (expected %v)\nDay:%v (expected %v)",
			certYear,
			expectYear,
			certMonth,
			expectMonth,
			certDay,
			expectDay,
		))
	}

	//privKey
	if certSetVals.PrivateKey.(*ecdsa.PrivateKey).Params().Name != "P-521" {
		t.Error("Incorrect curve name: " + certSetVals.PrivateKey.(*ecdsa.PrivateKey).Params().Name)
	}

	// TODO this should be its own test case
	//test having unset values works to randomise that attribute
	x5Certs := []*x509.Certificate{}
	tlsCerts := []*tls.Certificate{}
	for i := 0; i < 10; i++ {
		certRand1, err := GenerateTLSCert(nil, nil, nil, nil, nil,
			nil, true) //making rsa to test enc/dec good
		if err != nil {
			t.Fatal("Certificate generation[2] error:" + err.Error())
		}
		tlsCerts = append(tlsCerts, certRand1)
		x5CertRand1, err := x509.ParseCertificate(certRand1.Certificate[0])
		if err != nil {
			t.Fatal("Certificate generation[5] error:" + err.Error())
		}
		x5Certs = append(x5Certs, x5CertRand1)
	}

	for i, cer := range x5Certs {
		//checking values in isolation

		//test generated times are accurate

		//timeBefore must be before today
		if cer.NotBefore.After(time.Now()) {
			t.Error("Generated time incorrect:", cer.NotBefore, "(today: ", time.Now(), ")")
		}
		//timeBefore must not be longer ago than 1 year
		if cer.NotBefore.Before(time.Now().AddDate(-1, 0, 0)) {
			t.Error("Generated time before too long ago: ", cer.NotBefore, time.Now())
		}
		//timeAfter must be 2 years after timeBefore
		certYear, certMonth, certDay := cer.NotBefore.Date()
		acertYear, acertMonth, acertDay := cer.NotAfter.Date()
		if acertYear != (certYear+2) || certDay != acertDay || certMonth != acertMonth {
			t.Error("Generated times for cert after inconsistent. Got:", acertYear, acertMonth, acertDay,
				"Expected:", certYear+2, certMonth, certDay)
		}

		//comparing certificates against other certificates
		for ii, cer2 := range x5Certs {

			if i == ii {
				continue //don't compare same values
			}
			//check serial is different
			if cer.SerialNumber.Cmp(cer2.SerialNumber) == 0 { //same value :(
				t.Error(fmt.Errorf("serial numbers generated are the same: %d and %d: %v",
					i,
					ii,
					cer.SerialNumber.Int64()))
			}
		}
	}

	k1 := tlsCerts[0].PrivateKey.(*rsa.PrivateKey)
	k1pub := k1.Public().(*rsa.PublicKey)
	k2 := tlsCerts[1].PrivateKey.(*rsa.PrivateKey)
	k2pub := k2.Public().(*rsa.PublicKey)

	//test the certificates priv/pub are correct (can use for enc/dec operations)
	plain1 := []byte("plainmessage1")
	plain2 := []byte("plainmsg2")

	ct1, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, k1pub, plain1, []byte{})
	if err != nil {
		t.Error("Error during encrypt/decrypt verification 1: ", err)
	}
	ct2, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, k2pub, plain2, []byte{})
	if err != nil {
		t.Error("Error during encrypt/decrypt verification 2: ", err)
	}

	dec1, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, k1, ct1, []byte{})
	if err != nil {
		t.Error("Error during encrypt/decrypt verification 3: ", err)
	}

	dec2, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, k2, ct2, []byte{})
	if err != nil {
		t.Error("Error during encrypt/decrypt verification 4: ", err)
	}

	if !bytes.Equal(dec1, plain1) || !bytes.Equal(dec2, plain2) {
		t.Error("Error during encrypt/decrypt verification 5: decrypted values don't match (",
			string(plain1),
			string(dec1),
			"), (",
			string(plain2),
			string(dec2),
			")",
		)
	}

	//todo: test certificates generated can be used for TLS operations
}
