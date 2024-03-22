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
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	// 3rd Party
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/emptypb"

	// Internal
	"github.com/Ne0nd0g/merlin/v2/pkg/client"
	"github.com/Ne0nd0g/merlin/v2/pkg/client/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/client/message"
	memoryMessage "github.com/Ne0nd0g/merlin/v2/pkg/client/message/memory"
	"github.com/Ne0nd0g/merlin/v2/pkg/logging"
	"github.com/Ne0nd0g/merlin/v2/pkg/modules/socks"
	pb "github.com/Ne0nd0g/merlin/v2/pkg/rpc"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/agent"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/job"
	"github.com/Ne0nd0g/merlin/v2/pkg/services/listeners"
)

// Server is the structure used with the RPC service
type Server struct {
	pb.UnimplementedMerlinServer
	messageChan  map[uuid.UUID]chan *pb.Message // messageChan is a channel of messages to send to the client
	ls           listeners.ListenerService      // ls is the service used to interact with the Listeners service on the server
	clientRepo   client.Repository              // clientRepo is the repository (data store) of CLI clients connected to the RPC server
	messageRepo  message.Repository             // messageRepo is the repository (data store) of messages to send to connected CLI clients
	agentService *agent.Service                 // agentService is the service used to interact with the Agents service on the server
	jobService   *job.Service                   // jobService is the service used to interact with the agent Job service on the server

}

// Service holds the implementation of the RPC Server structure as a service
type Service struct {
	rpcServer *Server
	password  string // password is the string that connecting RPC clients must have
	tlsConfig *tls.Config
}

// services in the instantiated Service structure for this CLI service
var service *Service

// newServer is a factory to create a new Server structure that holds references to server-side repositories and services
func newServer() *Server {
	return &Server{
		messageChan:  make(map[uuid.UUID]chan *pb.Message),
		ls:           listeners.NewListenerService(),
		clientRepo:   withMemoryClientRepository(),
		messageRepo:  withMemoryClientMessageRepository(),
		agentService: agent.NewAgentService(),
		jobService:   job.NewJobService(),
	}
}

// NewRPCService is a factory to instantiate the server-side RPC Service, and it's an embedded Server structure
func NewRPCService(password string, secure bool, tlsCert, tlsKey, tlsCA string) (*Service, error) {
	// Setup the logger
	logging.Run()

	if service == nil {
		service = &Service{
			rpcServer: newServer(),
			password:  password,
		}
		var err error
		service.tlsConfig, err = getTLSConfig(secure, tlsKey, tlsCert, tlsCA)
		if err != nil {
			return nil, fmt.Errorf("there was an error creating a new RPC service: %s", err)
		}
	}
	return service, nil
}

// withMemoryClientRepository creates and returns a new in-memory repository for RPC clients to this server
func withMemoryClientRepository() client.Repository {
	return memory.NewRepository()
}

// withMemoryClientMessageRepository creates and returns a new in-memory repository for messages to be sent to RCP clients
func withMemoryClientMessageRepository() message.Repository {
	return memoryMessage.NewRepository()
}

/* SERVER */

// Listen provides a stream of messages for a CLI client
func (s *Server) Listen(in *pb.ID, stream pb.Merlin_ListenServer) error {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "in", in)
	// Parse the UUID from the request
	id, err := uuid.Parse(in.Id)
	if err != nil {
		return err
	}

	// Validate the channel exists
	if _, ok := s.messageChan[id]; !ok {
		//return fmt.Errorf("a channel for client ID %s does not exist", id)
		s.messageChan[id] = make(chan *pb.Message, 100)
	}

	for {
		select {
		case msg := <-s.messageChan[id]:
			if err = stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

// ListenForClientMessages is an infinite routine listening for RPC client messages from the server to send to the client
func (s *Server) ListenForClientMessages() {
	for {
		msg := s.messageRepo.GetQueue()
		for clientID := range s.messageChan {
			s.messageChan[clientID] <- NewPBMessageFromMessage(msg)
		}
	}
}

// Reconnect is used by RPC client's to re-establish a connection to the RPC server
func (s *Server) Reconnect(ctx context.Context, id *pb.ID) (*pb.ID, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "id", id)
	// Parse the UUID from the request
	clientID, err := uuid.Parse(id.Id)
	if err != nil {
		return nil, err
	}

	// See if the client already exists
	_, err = s.clientRepo.Get(clientID)

	// If the client doesn't exist, create it
	if err != nil {
		cliClient := client.NewClientWithID(clientID)
		s.clientRepo.Add(cliClient)
		s.messageChan[cliClient.ID()] = make(chan *pb.Message, 100)
		slog.Info(fmt.Sprintf("Re-registered new RPC client with ID %s", cliClient.ID()))
	}
	return &pb.ID{Id: clientID.String()}, nil
}

// Register is used by CLI clients to register with the RPC server
func (s *Server) Register(ctx context.Context, e *emptypb.Empty) (*pb.ID, error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "empty", e)
	cliClient := client.NewClient()
	s.clientRepo.Add(cliClient)
	s.messageChan[cliClient.ID()] = make(chan *pb.Message, 100)
	slog.Info(fmt.Sprintf("Registered new RPC client with ID %s", cliClient.ID()))
	return &pb.ID{Id: cliClient.ID().String()}, nil
}

// Socks creates a TCP listener on the provided port and forwards SOCKS5 traffic to the provided agent
// in.Arguments[0] = method
// in.Arguments[1] = interface:port
// in.Arguments[2] = agent ID
func (s *Server) Socks(ctx context.Context, in *pb.AgentCMD) (msg *pb.Message, err error) {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "context", ctx, "in", in)
	if len(in.Arguments) < 1 {
		err = fmt.Errorf("the Socks RPC call requires at least one argument, have (%d): %s", len(in.Arguments), in.Arguments)
		slog.Error(err.Error())
		return
	}

	// Parse the UUID from the request
	agentID, err := uuid.Parse(in.ID)
	if err != nil {
		err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", in.ID, err)
		slog.Error(err.Error())
		return
	}

	// Set the SOCKS options
	options := make(map[string]string)
	options["agent"] = agentID.String()
	options["interface"] = "127.0.0.1"
	options["port"] = "9050"
	options["command"] = in.Arguments[0]

	switch strings.ToLower(in.Arguments[0]) {
	case "list":
		socksListeners := socks.GetListeners()
		var data string
		header := "\n\tAgent\t\t\t\tInterface:Port\n"
		header += "==========================================================\n"
		if len(socksListeners) > 0 {
			data += header
			for _, v := range socksListeners {
				data += fmt.Sprintf("%s\t%s\n", v[0], v[1])
			}
		} else {
			data = "there are currently 0 SOCKS5 listeners"
		}
		msg = NewPBInfoMessage(data)
		return
	case "start":
		if len(in.Arguments) < 3 {
			err = fmt.Errorf("the Socks 'start' RPC call requires three arguments, have (%d): %s", len(in.Arguments), in.Arguments)
			slog.Error(err.Error())
			return
		}
		// Arguments 1. start/stop 2. interface:port
		if strings.Contains(in.Arguments[1], ":") {
			i := strings.Split(in.Arguments[1], ":")
			if len(i) > 1 {
				options["interface"] = i[0]
				options["port"] = i[1]
			}
		} else {
			options["port"] = in.Arguments[1]
		}
	case "stop":
		options["command"] = "stop"
	default:
		err = fmt.Errorf("unknown SOCKS command: %s", in.Arguments[0])
	}

	result, err := socks.Parse(options)
	if err != nil {
		err = fmt.Errorf("there was an error parsing the SOCKS command: %s", err)
		slog.Error(err.Error())
		return
	}
	msg = NewPBNoteMessage(strings.Join(result, " "))
	return
}

/* SERVICE */

// authentication is a gRPC interceptor that checks the incoming connection for the correct password
func (s *Service) authentication(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var rpcClient string
	peerClient, k := peer.FromContext(ctx)
	if !k {
		slog.Warn("unable to get the peer from the request context", "Method", info.FullMethod)
	} else {
		rpcClient = peerClient.Addr.String()
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		slog.Warn("incoming connection did not contain metadata", "Method", info.FullMethod, "Client", rpcClient)
		return nil, fmt.Errorf("access denied")
	}
	auth := md["authorization"]
	if len(auth) < 1 {
		slog.Warn("incoming connection context did not contain 'authorization' metadata", "Method", info.FullMethod, "Client", rpcClient)
		return nil, fmt.Errorf("access denied")
	}
	if strings.Join(auth, "") != s.password {
		slog.Debug("incoming connection context contained the wrong password", "password", auth, "Method", info.FullMethod, "Client", rpcClient)
		slog.Warn("incoming connection context did not contain the correct password", "Method", info.FullMethod, "Client", rpcClient)
		return nil, fmt.Errorf("access denied")
	}
	slog.Debug("authentication successful", "Method", info.FullMethod, "Client", rpcClient)
	return handler(ctx, req)
}

// authenticationStream is a gRPC interceptor that checks the incoming stream for the correct password
func (s *Service) authenticationStream(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	var rpcClient string
	peerClient, k := peer.FromContext(stream.Context())
	if !k {
		slog.Warn("unable to get the peer from the request context", "Method", info.FullMethod, "Client", rpcClient)
	} else {
		rpcClient = peerClient.Addr.String()
	}

	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		slog.Warn("incoming connection did not contain metadata", "Method", info.FullMethod, "Client", rpcClient)
		return fmt.Errorf("access denied")
	}
	auth := md["authorization"]
	if len(auth) < 1 {
		slog.Warn("incoming connection context did not contain 'authorization' metadata", "Method", info.FullMethod, "Client", rpcClient)
		return fmt.Errorf("access denied")
	}
	if strings.Join(auth, "") != s.password {
		slog.Debug("incoming connection context contained the wrong password", "password", auth, "Method", info.FullMethod, "Client", rpcClient)
		slog.Warn("incoming connection context did not contain the correct password", "Method", info.FullMethod, "Client", rpcClient)
		return fmt.Errorf("access denied")
	}
	slog.Debug("authentication successful", "Method", info.FullMethod, "Client", rpcClient)
	return handler(srv, stream)
}

// Run is the primary entry point for start and run this RPC service
func (s *Service) Run(addr string, listenersStorageFile string) error {
	slog.Log(context.Background(), logging.LevelTrace, "entering into function", "addr", addr)
	// Setup network listener
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("there was an error trying to listen on %s: %s", addr, err)
	}

	// Create a new gRPC server
	var opts []grpc.ServerOption
	opts = append(opts, grpc.UnaryInterceptor(s.authentication))
	opts = append(opts, grpc.StreamInterceptor(s.authenticationStream))
	opts = append(opts, grpc.Creds(credentials.NewTLS(s.tlsConfig)))
	grpcServer := grpc.NewServer(opts...)

	// Register the server with the gRPC server
	pb.RegisterMerlinServer(grpcServer, s.rpcServer)

	go s.rpcServer.ListenForClientMessages()

	if listenersStorageFile != "" {
		service.rpcServer.ls.SetStorageFile(listenersStorageFile)
		if _, err := os.Stat(listenersStorageFile); err == nil {
			err = service.rpcServer.ls.LoadListenersFromFile(listenersStorageFile)
			if err != nil {
				return err
			}
		} else if errors.Is(err, os.ErrNotExist) {
			slog.Debug(fmt.Sprintf("File %s does not exist, it will be created", listenersStorageFile))
			f, err := os.Create(listenersStorageFile)
			if err != nil {
				return err
			}
			defer f.Close()
			slog.Debug(fmt.Sprintf("File %s, was created", listenersStorageFile))
		}
	}

	// Start the gRPC server
	log.Printf("Starting gRPC server on %s", addr)
	err = grpcServer.Serve(lis)
	if err != nil {
		return fmt.Errorf("there was an error serving the gRPC connection: %s", err)
	}
	return nil
}

// SendClientMessage sends a message to all connected CLI clients
func (s *Service) SendClientMessage(msg *message.Message) {
	for cliClient := range s.rpcServer.messageChan {
		s.rpcServer.messageChan[cliClient] <- NewPBMessageFromMessage(msg)
	}
}

// NewPBErrorMessage creates an RPC client message from an error
func NewPBErrorMessage(err error) *pb.Message {
	return &pb.Message{
		Level:     pb.MessageLevel_WARN,
		Message:   validUTF8(err.Error()),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Error:     true,
	}
}

// NewPBSuccessMessage create a "success" RPC client message
func NewPBSuccessMessage(msg string) *pb.Message {
	return &pb.Message{
		Level:     pb.MessageLevel_SUCCESS,
		Message:   validUTF8(msg),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// NewPBNoteMessage creates a "note" RPC client message
func NewPBNoteMessage(msg string) *pb.Message {
	return &pb.Message{
		Level:     pb.MessageLevel_NOTE,
		Message:   validUTF8(msg),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// NewPBInfoMessage Creates an "info" RPC client message
func NewPBInfoMessage(msg string) *pb.Message {
	return &pb.Message{
		Level:     pb.MessageLevel_INFO,
		Message:   validUTF8(msg),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// NewPBPlainMessage creates a "plain" RPC client message
func NewPBPlainMessage(msg string) *pb.Message {
	return &pb.Message{
		Level:     pb.MessageLevel_PLAIN,
		Message:   validUTF8(msg),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// NewPBWarnMessage creates a "warn" RPC client message
func NewPBWarnMessage(msg string) *pb.Message {
	return &pb.Message{
		Level:     pb.MessageLevel_WARN,
		Message:   validUTF8(msg),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// NewPBMessageFromMessage convert a message.Message into a client RPC message
func NewPBMessageFromMessage(msg *message.Message) *pb.Message {
	var level pb.MessageLevel
	switch msg.Level() {
	case message.Info:
		level = pb.MessageLevel_INFO
	case message.Note:
		level = pb.MessageLevel_NOTE
	case message.Warn:
		level = pb.MessageLevel_WARN
	case message.Debug:
		level = pb.MessageLevel_DEBUG
	case message.Success:
		level = pb.MessageLevel_SUCCESS
	case message.Plain:
		level = pb.MessageLevel_PLAIN
	default:
		level = pb.MessageLevel_UNDEFINED
	}
	return &pb.Message{
		Level:     level,
		Message:   validUTF8(msg.Message()),
		Timestamp: msg.Time().UTC().Format(time.RFC3339),
		Error:     msg.Error(),
	}
}

// validUTF8 ensures the string contains valid UTF-8 and replaces invalid characters with the '�' character
// gRPC messages must be valid UTF-8
func validUTF8(s string) string {
	// Ensure the message is a valid UTF-8 string
	if utf8.ValidString(s) {
		return s
	}
	return fmt.Sprintf(
		"\n*** The message contained invalid UTF-8 that was replaced with the '�' character ***\n\n%s",
		strings.ToValidUTF8(s, "�"),
	)
}

// getTLSConfig creates a new TLS configuration for the RPC service
func getTLSConfig(secure bool, tlsKey, tlsCert, tlsCA string) (*tls.Config, error) {
	slog.Debug("entering into function", "secure", secure, "tlsKey", tlsKey, "tlsCert", tlsCert)
	tlsConfig := &tls.Config{
		ClientAuth: tls.NoClientCert,
		MinVersion: tls.VersionTLS12,
	}
	if secure {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	// If a TLS Certificate Authority filepath was provided, load it
	if tlsCA != "" {
		// See if a valid filepath was provided for the tlsCA
		_, err := os.Stat(tlsCA)
		if err != nil {
			return nil, fmt.Errorf("there was an error getting TLS CA file information for '%s': %s", tlsCA, err)
		}

		// Read the TLS CA file in as bytes
		caBytes, err := os.ReadFile(tlsCA) // #nosec G304 Users can include any file they want
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

		// Add the CertPool to the TLS configuration to validate client certificates
		if secure {
			tlsConfig.ClientCAs = certPool
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
		certBytes, err := os.ReadFile(tlsCert) // #nosec G304 Users can include any file they want
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
		return nil, fmt.Errorf("there was an error generating a new RSA key: %s", err)
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
