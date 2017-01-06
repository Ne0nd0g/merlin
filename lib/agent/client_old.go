package main

import (
	"fmt"
	"net/http"
	"crypto/tls"
)

func main() {

	//u := "https://http2.golang.org/"
	u := "https://205.232.71.92:80"
	fmt.Println("[-]Connecting to web server at ", u)

	tr1 := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			InsecureSkipVerify:       true,
			PreferServerCipherSuites: false,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			},
			NextProtos: []string{"http/1.1",}, //if you add h2 then it will fail
		},
		TLSNextProto: nil,
		DisableCompression: false,
	}

	// THE PROBLEM IS THAT WHEN A TLSClientConfig is specified with something other than nil, HTTP/1.1 is used
	tr2 := &http.Transport{
		TLSClientConfig: nil,
		TLSNextProto: nil,
	}

	client1 := &http.Client{
		Transport: tr1,
	}
	resp1, err1 := client1.Get(u)

	if err1 != nil {
		fmt.Println("ERROR!")
		fmt.Println(err1)
	}

	client2 := &http.Client{
		Transport: tr2,
	}
	resp2, err2 := client2.Get(u)

	if err2 != nil {
		fmt.Println("ERROR!")
		fmt.Println(err2)
	}

	fmt.Println("[-]HTTP Protocol & Status:")
	fmt.Println("R1: ", resp1.Proto, resp1.Status)
	fmt.Println("R2: ", resp2.Proto, resp2.Status)
	fmt.Println("[-]Transport")
	fmt.Println("R1: ", tr1)
	fmt.Println("R2: ", tr2)
	fmt.Println("[-]Transport TLSNextProto")
	fmt.Println("R1: ", tr1.TLSNextProto)
	fmt.Println("R2: ", tr2.TLSNextProto)
	fmt.Println("[-]TLSClientConfig NextProtos")
	fmt.Println("R1: ", tr1.TLSClientConfig.NextProtos)
	fmt.Println("R2: ", tr2.TLSClientConfig.NextProtos)
}
