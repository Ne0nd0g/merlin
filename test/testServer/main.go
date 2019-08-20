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

package testserver

import (
	// Standard
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	// 3rd Party
	"github.com/satori/go.uuid"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

var verbose = false

func (ts *TestServer) handler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.RequestURI == "/isup" {
		w.WriteHeader(200)
		return
	}

	// Make sure the message has a JWT
	token := r.Header.Get("Authorization")
	if token == "" {
		w.WriteHeader(404)
		return
	}
	//Read the request message until EOF
	requestBytes, errRequestBytes := ioutil.ReadAll(r.Body)
	if errRequestBytes != nil {
		if verbose {
			fmt.Println(fmt.Sprintf("there was an error reading the request message:\r\n%s", errRequestBytes.Error()))
		}
		w.WriteHeader(500)
		return
	}

	// Decode gob to JWE string
	var jweString string
	errDecode := gob.NewDecoder(bytes.NewReader(requestBytes)).Decode(&jweString)
	if errDecode != nil {
		if verbose {
			fmt.Println(fmt.Sprintf("there was an error decoding the message from gob to JWE string:\r\n%s", errDecode.Error()))
		}
		w.WriteHeader(500)
		return
	}

	// Validate JWT and get claims
	var agentID uuid.UUID
	var errValidate error

	hashedKey := sha256.Sum256([]byte("test"))
	key := hashedKey[:]

	agentID, errValidate = validateJWT(strings.Split(token, " ")[1], []byte("xZF7fvaGD6p2yeLyf9i7O9gBBHk05B0u"))
	if errValidate != nil {
		// Validate JWT using interface PSK; Used by unauthenticated agents
		hashedKey := sha256.Sum256([]byte("test"))
		key := hashedKey[:]
		agentID, errValidate = validateJWT(strings.Split(token, " ")[1], key)
		if errValidate != nil {
			w.WriteHeader(404)
			return
		}
	}

	if len(agents.GetEncryptionKey(agentID)) > 0 {
		key = agents.GetEncryptionKey(agentID)
	}

	// Decrypt JWE
	j, errDecryptPSK := decryptJWE(jweString, key)
	if errDecryptPSK != nil {
		if verbose {
			fmt.Println(fmt.Sprintf("there was an error decrypting the JWE on the server:\r\n%s", errDecryptPSK.Error()))
		}
		w.WriteHeader(500)
		return
	}

	//fmt.Println(fmt.Sprintf("Request: %+v\nBody:%+v", r, j)) //uncomment here if you want to print out exactly what the test server receives

	var returnMessage messages.Base
	var err error

	// User Agent based actions
	switch r.UserAgent() {
	case "invalidMessageBaseType":
		returnMessage.Type = "Test"
	}

	// Message type based action
	switch j.Type {
	case "AgentInfo":
		err = agents.UpdateInfo(j)
	case "AuthInit":
		returnMessage, err = agents.OPAQUEAuthenticateInit(j)
	case "AuthComplete":
		returnMessage, err = agents.OPAQUEAuthenticateComplete(j)
	case "BadPayload":
		w.Header().Set("Content-Type", "application/octet-stream")
		errBadPayload := gob.NewEncoder(w).Encode([]byte("Hack the planet!"))
		if errBadPayload != nil {
			fmt.Println(errBadPayload.Error())
		}
	default:

	}

	if err != nil {
		log.Fatal(err)
	}
	returnMessage.ID = agentID
	// Encode messages.Base into a gob
	returnMessageBytes := new(bytes.Buffer)
	errReturnMessageBytes := gob.NewEncoder(returnMessageBytes).Encode(returnMessage)
	if errReturnMessageBytes != nil {
		if verbose {
			fmt.Println(fmt.Sprintf("there was an error encoding the return message into a gob:\r\n%s", errReturnMessageBytes.Error()))
		}
		w.WriteHeader(500)
		return
	}

	// Get JWE
	jwe, errJWE := core.GetJWESymetric(returnMessageBytes.Bytes(), key[:])
	if errJWE != nil {
		if verbose {
			fmt.Println(fmt.Sprintf("there was an error encrypting the message into a JWE:\r\n%s", errJWE.Error()))
		}
		w.WriteHeader(500)
		return
	}

	// Encode JWE to GOB and send it to the agent
	w.Header().Set("Content-Type", "application/octet-stream")
	errEncode := gob.NewEncoder(w).Encode(jwe)
	if errEncode != nil {
		if verbose {
			fmt.Println(fmt.Sprintf("there was an error encoding the JWE into a gob:\r\n%s", errEncode.Error()))
		}
		w.WriteHeader(500)
		return
	}
}

//TestServer is a webserver instance that facilitates functional testing of code that requires the ability to send web requests
type TestServer struct {
	tes *testing.T
}

//since tls/pki is such a pain this generate them every time
func generateTLSConfig() *tls.Config {
	//https://golang.org/src/crypto/tls/generate_cert.go taken from here mostly
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}
	tpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "127.0.0.1",
			Organization: []string{"Joey is the best hacker in Hackers"},
		},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"127.0.0.1", "localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Minute * 20),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	crtBytes, e := x509.CreateCertificate(rand.Reader, &tpl, &tpl, priv.Public(), priv)
	if e != nil {
		panic(e)
	}

	crt := tls.Certificate{
		Certificate: [][]byte{crtBytes},
		PrivateKey:  priv,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{crt},
		NextProtos:   []string{"h2", "hq"},
	}
}

//Start starts the test HTTP server
func (TestServer) Start(port string, finishedTest, setup chan struct{}, t *testing.T) {
	s := http.NewServeMux()
	ts := TestServer{
		tes: t,
	}
	s.HandleFunc("/", ts.handler)
	srv := http.Server{}

	srv.TLSConfig = generateTLSConfig()
	srv.Handler = s
	srv.Addr = "127.0.0.1:" + port
	go func() {
		ln, e := net.Listen("tcp", srv.Addr)

		defer func() {
			err := ln.Close()
			if err != nil {
				log.Fatal(err)
			}
		}()

		if e != nil {
			panic(e)
		}
		tlsListener := tls.NewListener(ln, srv.TLSConfig)
		e = srv.Serve(tlsListener)
		if e != nil { //should be set by the tls config
			panic(e)
		}
	}()
	for {
		time.Sleep(time.Second * 1)
		/* #nosec G402 */
		// G402: TLS InsecureSkipVerify set true. (Confidence: HIGH, Severity: HIGH) Allowed for testing
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		resp, err := client.Get("https://localhost:" + port + "/isup")
		if err != nil {
			continue
		}
		errC := resp.Body.Close()
		if errC != nil {
			log.Fatalf("There was an error closing the body:\r\n%s", errC)
		}
		if resp.StatusCode != http.StatusOK {
			continue
		}
		// Reached this point: server is up and running!
		break
	}

	close(setup)
	<-finishedTest //this is an ultra gross hack :(
}

// decryptJWE takes provided JWE string and decrypts it using the per-agent key
func decryptJWE(jweString string, key []byte) (messages.Base, error) {
	var m messages.Base

	// Parse JWE string back into JSONWebEncryption
	jwe, errObject := jose.ParseEncrypted(jweString)
	if errObject != nil {
		return m, fmt.Errorf("there was an error parseing the JWE string into a JSONWebEncryption object:\r\n%s", errObject)
	}

	// Decrypt the JWE
	jweMessage, errDecrypt := jwe.Decrypt(key)
	if errDecrypt != nil {
		return m, fmt.Errorf("there was an error decrypting the JWE:\r\n%s", errDecrypt.Error())
	}

	// Decode the JWE payload into a messages.Base struct
	errDecode := gob.NewDecoder(bytes.NewReader(jweMessage)).Decode(&m)
	if errDecode != nil {
		return m, fmt.Errorf("there was an error decoding JWE payload message sent by an agent:\r\n%s", errDecode.Error())
	}

	return m, nil
}

// validateJWT validates the provided JSON Web Token
func validateJWT(agentJWT string, key []byte) (uuid.UUID, error) {
	var agentID uuid.UUID

	claims := jwt.Claims{}

	// Parse to make sure it is a valid JWT
	nestedToken, err := jwt.ParseSignedAndEncrypted(agentJWT)
	if err != nil {
		return agentID, fmt.Errorf("there was an error parsing the JWT:\r\n%s", err.Error())
	}

	// Decrypt JWT
	token, errToken := nestedToken.Decrypt(key)
	if errToken != nil {
		return agentID, fmt.Errorf("there was an error decrypting the JWT:\r\n%s", errToken.Error())
	}

	// Deserialize the claims and validate the signature
	errClaims := token.Claims(key, &claims)
	if errClaims != nil {
		return agentID, fmt.Errorf("there was an deserializing the JWT claims:\r\n%s", errClaims.Error())
	}

	// Validate claims
	errValidate := claims.Validate(jwt.Expected{
		Time: time.Now(),
	})
	if errValidate != nil {
		return agentID, errValidate
	}
	agentID = uuid.FromStringOrNil(claims.ID)
	return agentID, nil
}
