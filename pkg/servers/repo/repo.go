package repo

import (
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/servers"
	"github.com/Ne0nd0g/merlin/pkg/servers/http"
	"github.com/Ne0nd0g/merlin/pkg/servers/http2"
	"github.com/Ne0nd0g/merlin/pkg/servers/http3"
	"github.com/Ne0nd0g/merlin/pkg/servers/tcp"
	"strings"
)

// New instantiates a Listener object
func New(options map[string]string) (servers.ServerInterface, error) {
	switch strings.ToLower(options["Protocol"]) {
	case "http", "https", "http2":
		return http.New(options)
	case "h2c":
		return http2.New(options)
	case "http3":
		return http3.New(options)
	case "tcp":
		return tcp.New(options)
	default:
		return nil, fmt.Errorf("invalid listener server type: %s", options["Protocol"])
	}
}

// GetListenerOptions returns all of the configurable options for an uninstatiated listener based on the provided protocol type
func GetProtocolOptionDefaults(protocol string) map[string]string {
	var options map[string]string
	switch strings.ToLower(protocol) {
	case "http", "https", "http2":
		options = http.GetOptions(strings.ToLower(protocol))
	case "h2c":
		options = http2.GetOptions()
	case "http3":
		options = http3.GetOptions()
	case "tcp":
		options = tcp.GetOptions()
	default:
		options = make(map[string]string)
	}

	options["Name"] = "Default"
	options["Description"] = "Default listener"
	return options
}

// GetListenerOptionsCompleter returns CLI tab completer for supported Listener server protocols
func GetProtocolOptionDefaultsCompletor(protocol string) func(string) []string {
	return func(line string) []string {
		var serverOptions map[string]string
		options := make([]string, 0)
		switch strings.ToLower(protocol) {
		case "http", "https", "http2":
			serverOptions = http.GetOptions(strings.ToLower(protocol))
		case "h2c":
			serverOptions = http2.GetOptions()
		case "http3":
			serverOptions = http3.GetOptions()
		case "tcp":
			serverOptions = tcp.GetOptions()
		default:
			serverOptions = make(map[string]string)
		}
		for k := range serverOptions {
			options = append(options, k)
		}
		options = append(options, "Name")
		options = append(options, "Description")
		return options
	}
}
