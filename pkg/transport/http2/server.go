package http2

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Ne0nd0g/merlin/pkg/logging"
	"github.com/Ne0nd0g/merlin/pkg/transport"
	"github.com/Ne0nd0g/merlin/pkg/util"
	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
)

// Server is a structure for creating and instantiating new server objects
type HTTP2CommServer struct {
	Interface   string
	Port        int
	Protocol    string
	Key         string
	Certificate string
	Server      interface{}
	Mux         *http.ServeMux
	SrvHandler  func(w io.Writer, r io.Reader)
}

func (s HTTP2CommServer) Run() error {

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

func NewServer(iface string, port int, protocol string, key string, certificate string) (*HTTP2CommServer, error) {
	s := &HTTP2CommServer{
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

	srv := &http.Server{
		Addr:           s.Interface + ":" + strconv.Itoa(s.Port),
		Handler:        s.Mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      TLSConfig,
	}
	s.Mux.HandleFunc("/", s.wrapperFunc)
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

func (s *HTTP2CommServer) RegisterHandler(f func(w io.Writer, r io.Reader)) transport.MerlinServerClient {
	message("note", "Registered http2 handler")
	s.SrvHandler = f
	return s
}

func (s *HTTP2CommServer) wrapperFunc(w http.ResponseWriter, r *http.Request) {
	if s.SrvHandler == nil {
		message("info", "srv handler not set up..")
		return
	}

	bod, err := ioutil.ReadAll(r.Body)
	if err != nil {
		message("err", "error reading request body: "+err.Error())
	}
	readr := bytes.NewReader(bod)
	s.SrvHandler(w, readr)

}
