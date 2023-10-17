/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2023  Russel Van Tuyl

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

// Package rpc provides the gRPC client for communicating with the Merlin server
package rpc

import (
	// Standard
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"

	// 3rd Party
	uuid "github.com/satori/go.uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/cli/message"
	mmemory "github.com/Ne0nd0g/merlin/pkg/cli/message/memory"
	pb "github.com/Ne0nd0g/merlin/pkg/cli/rpc"
)

// Service is the structure that holds all the connections for the service to operate
type Service struct {
	id            uuid.UUID              // id is the unique id of this service
	rpcAddr       string                 // rpcAddr is the RPC server address
	merlinClient  pb.MerlinClient        // merlinClient is the gRPC client for the Merlin service
	messageStream pb.Merlin_ListenClient // messageStream is a gRPC stream to listen for messages from the RPC server
	cliClientID   uuid.UUID              // cliClientID is the UUID of the CLI client used to send messages to the repository
	messageRepo   message.Repository     // messageRepo is the repository of user messages displayed on the CLI
	password      string                 // password is the RPC client password used to authenticate to the server
	tlsConfig     *tls.Config
}

// service in the instantiated Service structure for this CLI service
var service *Service

// NewRPCService is a factory that returns an instantiated RPC Service
func NewRPCService(password string, secure bool, tlsKey, tlsCert, tlsCA string) (*Service, error) {
	if service == nil {
		service = &Service{
			messageRepo: withMemoryMessageRepository(),
			password:    password,
		}
		var err error
		service.tlsConfig, err = getTLSConfig(secure, tlsKey, tlsCert, tlsCA)
		if err != nil {
			return nil, fmt.Errorf("there was an error creating a new RPC services: %s", err)
		}

	}
	return service, nil
}

// withMemoryMessageRepository calls a factory that creates a new in-memory message repository
func withMemoryMessageRepository() message.Repository {
	return mmemory.NewRepository()
}

// authenticate is a gRPC interceptor that adds the password to the outgoing context for single connections
func (s *Service) authenticate(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", s.password)
	return invoker(ctx, method, req, reply, cc, opts...)
}

// authenticateStream is a gRPC interceptor that adds the password to the outgoing context for streams
func (s *Service) authenticateStream(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", s.password)
	return streamer(ctx, desc, cc, method, opts...)
}

// Connect establish a connection with the gRPC server
func (s *Service) Connect(addr string) error {
	s.rpcAddr = addr
	var opts []grpc.DialOption

	// Setup TLS credentials
	if s.tlsConfig != nil {
		if s.tlsConfig.RootCAs != nil {
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(s.tlsConfig)))
		} else {
			opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
	}

	opts = append(opts, grpc.WithUnaryInterceptor(s.authenticate))
	opts = append(opts, grpc.WithStreamInterceptor(s.authenticateStream))
	opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(s.tlsConfig)))

	conn, err := grpc.Dial(addr, opts...)

	if err != nil {
		return fmt.Errorf("there was an error connecting to %s: %s", addr, err)
	}

	// Create a new gRPC client
	s.merlinClient = pb.NewMerlinClient(conn)

	// Call the Register method
	id, err := s.merlinClient.Register(context.Background(), &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("there was an error calling the Register method: %s", err)
	}

	// Convert UUID from string
	s.id, err = uuid.FromString(id.Id)
	if err != nil {
		return fmt.Errorf("there was an error converting the UUID from the server: %s", err)
	}

	msg := message.NewUserMessage(message.Success, fmt.Sprintf("Succesfully connected to Merlin server at %s", addr))
	s.messageRepo.Add(msg)

	// Create a stream to listen for messages from the server
	if s.messageStream == nil {
		s.messageStream, err = s.merlinClient.Listen(context.Background(), id)
		if err != nil {
			return fmt.Errorf("there was an error calling the Listen method: %s", err)
		}
		go s.listen()
	}
	return nil
}

// Reconnect re-establish a connection with the RPC server after the connection was previously broken
func Reconnect() (msg *message.UserMessage) {
	if service.id == uuid.Nil {
		err := service.Connect(service.rpcAddr)
		if err != nil {
			msg = message.NewErrorMessage(fmt.Errorf("there was an error reconnecting to the server: %s", err))
			service.messageStream = nil
			return
		}
		return
	}
	if service.messageStream != nil {
		err := service.messageStream.CloseSend()
		if err != nil {
			msg = message.NewErrorMessage(fmt.Errorf("there was an error closing the message stream: %s", err))
			return
		}
	}

	var err error
	service.messageStream, err = service.merlinClient.Listen(context.Background(), &pb.ID{Id: service.id.String()})
	if err != nil {
		msg = message.NewErrorMessage(fmt.Errorf("there was an error calling the Listen method: %s", err))
		return
	}
	go service.listen()
	msg = message.NewUserMessage(message.Success, fmt.Sprintf("Successfully reconnected to the server at %s", service.rpcAddr))
	return
}

// listen is a gRPC stream run as a go routine that listens for messages from the server
func (s *Service) listen() {
	for {
		msg, err := s.messageStream.Recv()
		if err != nil {
			usrMsg := message.NewErrorMessage(fmt.Errorf("there was an error receiving a message from the server stream: %s", err))
			s.messageRepo.Add(usrMsg)
			s.messageStream = nil
			return
		}
		s.messageRepo.Add(newUserMessageFromPBMessage(msg))
	}
}

// buildMessage is a helper function that builds a UserMessage from a protobuf message and error
func buildMessage(response *pb.Message, err error) (msg *message.UserMessage) {
	if err != nil {
		msg = message.NewErrorMessage(fmt.Errorf("there was an error making the RPC call: %s", err))
		return
	}
	msg = newUserMessageFromPBMessage(response)
	return
}

// newUserMessageFromPBMessage converts a protobuf client message into a client side UserMessage structure
func newUserMessageFromPBMessage(msg *pb.Message) (m *message.UserMessage) {
	var level message.Level
	switch msg.Level {
	case pb.MessageLevel_INFO:
		level = message.Info
	case pb.MessageLevel_NOTE:
		level = message.Note
	case pb.MessageLevel_WARN:
		level = message.Warn
	case pb.MessageLevel_DEBUG:
		level = message.Debug
	case pb.MessageLevel_SUCCESS:
		level = message.Success
	case pb.MessageLevel_PLAIN:
		level = message.Plain
	default:
		level = message.Undefined
	}
	t, err := time.Parse(time.RFC3339, msg.Timestamp)
	if err != nil {
		slog.Error(fmt.Sprintf("there was an error parsing this timestamp '%s': %s", msg.Timestamp, err))
	}
	return message.NewUserMessageFull(level, msg.Message, t, msg.Error)
}

// getTLSConfig creates a new TLS configuration for the RPC service
func getTLSConfig(secure bool, tlsKey, tlsCert, tlsCA string) (*tls.Config, error) {
	tlsConfig := &tls.Config{}
	if !secure {
		tlsConfig.InsecureSkipVerify = true
	}

	// If a TLS Certificate Authority filepath was provided, load it
	if tlsCA != "" {
		// See if a valid filepath was provided for the tlsCA
		_, err := os.Stat(tlsCA)
		if err != nil {
			return nil, fmt.Errorf("there was an error getting TLS CA file information for '%s': %s", tlsCA, err)
		}

		// Read the TLS CA file in as bytes
		caBytes, err := os.ReadFile(tlsCA)
		if err != nil {
			return nil, fmt.Errorf("there was an error reading the TLS CA file at '%s': %s", tlsCA, err)
		}

		// Decode the PEM data
		block, _ := pem.Decode(caBytes)
		if block == nil {
			return nil, fmt.Errorf("no PEM data was found in the TLS CA file at '%s'", tlsCA)
		}

		// Parse the Certificate
		var caCer *x509.Certificate
		caCer, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("there was an error parsing the TLS CA certificate at '%s': %s", tlsCA, err)
		}
		if !caCer.IsCA {
			return nil, fmt.Errorf("the TLS CA certificate at '%s' is not a valid CA certificate", tlsCA)
		}

		slog.Info(
			"loaded TLS CA certificate from disk",
			"Filepath", tlsCA,
			"Version", caCer.Version,
			"Serial", caCer.SerialNumber,
			"Issuer", caCer.Issuer,
			"Subject", caCer.Subject,
			"NotBefore", caCer.NotBefore,
			"NotAfter", caCer.NotAfter,
			"Extensions", caCer.Extensions,
			"ExtraExtensions", caCer.ExtraExtensions,
		)

		// Create a new CertPool and add the CA certificate to it
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to add the TLS CA certificate at '%s' to the CertPool", tlsCA)
		}

		if secure {
			tlsConfig.RootCAs = certPool
			tlsConfig.InsecureSkipVerify = false
		}
	}

	// If a TLS certificate and key filepath were provided, load them
	if tlsKey != "" && tlsCert != "" {
		// See if a valid filepath was provided for the tlsKey and tlsCert
		_, err := os.Stat(tlsKey)
		if err != nil {
			return nil, fmt.Errorf("there was an error getting TLS key file information for '%s': %s", tlsKey, err)
		}

		_, err = os.Stat(tlsCert)
		if err != nil {
			return nil, fmt.Errorf("there was an error getting TLS certificate file information for '%s': %s", tlsKey, err)
		}

		// Read the TLS certificate file in as bytes
		certBytes, err := os.ReadFile(tlsCert)
		if err != nil {
			return nil, fmt.Errorf("there was an error reading the TLS certificate file at '%s': %s", tlsCert, err)
		}

		// Decode the PEM data
		block, _ := pem.Decode(certBytes)
		if block == nil {
			return nil, fmt.Errorf("no PEM data was found in the TLS certificate file at '%s'", tlsCert)
		}

		// Parse the Certificate
		var pubCer *x509.Certificate
		pubCer, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("there was an error parsing the TLS certifcate certificate at '%s': %s", tlsCA, err)
		}

		// Load the TLS certificate and key
		var cer tls.Certificate
		cer, err = tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			return nil, fmt.Errorf("there was an error loading the X509 key pair: %s", err)
		}

		slog.Info(
			"loaded TLS certificate and key from disk",
			"tlsKey", tlsKey,
			"tlsCert", tlsCert,
			"Version", pubCer.Version,
			"Serial", pubCer.SerialNumber,
			"Issuer", pubCer.Issuer,
			"Subject", pubCer.Subject,
			"NotBefore", pubCer.NotBefore,
			"NotAfter", pubCer.NotAfter,
			"Extensions", pubCer.Extensions,
			"ExtraExtensions", pubCer.ExtraExtensions,
		)

		tlsConfig.Certificates = []tls.Certificate{cer}
		return tlsConfig, nil
	}

	// If a valid TLS certificate and key were not provided, create one
	pk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("there was an error creating a new RPC service: %s", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Merlin"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 371),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pk.Public(), pk)
	if err != nil {
		return nil, err
	}

	slog.Info(
		"Created new TLS certificate",
		"Serial", template.SerialNumber,
		"Subject", template.Subject.Organization,
		"NotBefore", template.NotBefore,
		"NotAfter", template.NotAfter,
	)

	newCert := tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  pk,
	}
	tlsConfig.Certificates = []tls.Certificate{newCert}

	return tlsConfig, nil
}
