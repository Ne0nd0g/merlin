// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2018  Russel Van Tuyl

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
	"net/http"
	"fmt"
	"encoding/json"
	"path/filepath"
	"os"
	"encoding/base64"
	"io/ioutil"
	"time"
	"crypto/tls"

	// 3rd Party
	"github.com/fatih/color"
	
	// Merlin
	"github.com/Ne0nd0g/merlin/pkg/core"
	"github.com/Ne0nd0g/merlin/pkg/agents"
	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/messages"
)

func handler(w http.ResponseWriter, r *http.Request) {
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
		json.NewDecoder(r.Body).Decode(&j)

		if core.Debug {
			message("debug",fmt.Sprintf("[DEBUG]POST DATA: %s", j))
		}
		switch j.Type {

		case "InitialCheckIn":
			var p messages.SysInfo
			json.Unmarshal(payload, &p)
			agents.InitialCheckIn(j, p)

		case "StatusCheckIn":
			w.Header().Set("Content-Type", "application/json")
			x := agents.StatusCheckIn(j)
			if core.Verbose {
				message("note", fmt.Sprintf("Sending " + x.Type + " message type to agent"))
			}
			json.NewEncoder(w).Encode(x)

		case "CmdResults":
			// TODO move to its own function
			var p messages.CmdResults
			json.Unmarshal(payload, &p)
			agents.Log(j.ID, fmt.Sprintf("Results for job: %s", p.Job))

			message("success", fmt.Sprintf("Results for job %s", p.Job))
			if len(p.Stdout) > 0 {
				agents.Log(j.ID, fmt.Sprintf("Command Results (stdout):\r\n%s", p.Stdout))
				message("success", fmt.Sprintf("%s", p.Stdout))
			}
			if len(p.Stderr) > 0 {
				agents.Log(j.ID, fmt.Sprintf("Command Results (stderr):\r\n%s", p.Stderr))
				message("warn",fmt.Sprintf("%s", p.Stderr))
			}

		case "AgentInfo":
			var p messages.AgentInfo
			json.Unmarshal(payload, &p)
			if core.Debug {
				message("debug", fmt.Sprintf("AgentInfo JSON object: %s", p))
			}
			agents.Info(j, p)
		case "FileTransfer":
			var p messages.FileTransfer
			json.Unmarshal(payload, &p)
			if p.IsDownload {
				agentsDir := filepath.Join(core.CurrentDir, "data", "agents")
				_, f := filepath.Split(p.FileLocation) // We don't need the directory part for anything
				if _, errD := os.Stat(agentsDir); os.IsNotExist(errD) {
					message("","[!]There was an error locating the agent's directory")
					message("",errD.Error())
				}
				message("success", fmt.Sprintf("Results for job %s", p.Job))
				downloadBlob, downloadBlobErr := base64.StdEncoding.DecodeString(p.FileBlob)

				if downloadBlobErr != nil {
					message("","[!]There was an error decoding the fileBlob")
					message("",downloadBlobErr.Error())
				} else {
					downloadFile := filepath.Join(agentsDir, j.ID.String(), f)
					writingErr := ioutil.WriteFile(downloadFile, downloadBlob, 0644)
					if writingErr != nil {
						message("warn",fmt.Sprintf("There was an error writing to : %s", p.FileLocation))
						message("warn",writingErr.Error())
					} else {
						message("success", fmt.Sprintf("Successfully downloaded file %s with a size of %d bytes from agent to %s",
							p.FileLocation,
							len(downloadBlob),
							downloadFile))
						agents.Log(j.ID, fmt.Sprintf("Successfully downloaded file %s with a size of %d bytes from" +
							" agent to %s",
							p.FileLocation,
							len(downloadBlob),
							downloadFile))
					}
				}
			}
		default:
			message("warn",fmt.Sprintf("Invalid Activity: %s", j.Type))
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

// StartListener starts an instance of the HTTP/2 server
func StartListener(port string, ip string, crt string, key string, webpath string) {

	logging.Server("Starting HTTP/2 Listener")
	logging.Server(fmt.Sprintf("Address: %s:%s%s", ip, port, webpath))
	logging.Server(fmt.Sprintf("x.509 Certificate %s", crt))
	logging.Server(fmt.Sprintf("x.509 Key %s", key))

	time.Sleep(45 * time.Millisecond) // Sleep to allow the shell to start up
	// Check to make sure files exist
	_, errCrt := os.Stat(crt)
	if errCrt != nil {
		message("warn", "There was an error importing the SSL/TLS x509 certificate")
		message("warn", errCrt.Error())
		return
	}

	_, errKey := os.Stat(key)
	if errKey != nil {
		message("warn","There was an error importing the SSL/TLS x509 key")
		message("warn", errKey.Error())
		logging.Server(fmt.Sprintf("There was an error importing the SSL/TLS x509 key\r\n%s", errKey.Error()))
		return
	}

	cer, err := tls.LoadX509KeyPair(crt, key)

	if err != nil {
		message("warn", "There was an error importing the SSL/TLS x509 key pair")
		message("warn", "Ensure a keypair is located in the data/x509 directory")
		message("warn", err.Error())
		logging.Server(fmt.Sprintf("There was an error importing the SSL/TLS x509 key pair\r\n%s",err.Error()))
		return
	}

	// Configure TLS
	config := &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		NextProtos: []string{"h2"},
	}
	http.HandleFunc(webpath, handler)

	s := &http.Server{
		Addr:           ip + ":" + port,
		Handler:        nil,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      config,
	}

	// I shouldn't need to specify the certs as they are in the config
	message("note", fmt.Sprintf("HTTPS Listener Started on %s:%s", ip, port))
	err2 := s.ListenAndServeTLS(crt, key)
	if err2 != nil {
		message("warn", "There was an error starting the web server")
		logging.Server(fmt.Sprintf("There was an error starting the web server\r\n%s", err2.Error()))
		return
	}
	// TODO determine scripts path and load certs by their absolute path
}

// message is used to print a message to the command line
func message (level string, message string) {
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
