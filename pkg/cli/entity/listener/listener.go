package listener

import uuid "github.com/satori/go.uuid"

type Listener struct {
	id       uuid.UUID
	options  map[string]string
	proto    string
	serverID uuid.UUID
}

func NewListener(proto string, options map[string]string) Listener {
	return Listener{
		id:      uuid.NewV4(),
		options: options,
		proto:   proto,
	}
}

func (l Listener) ID() uuid.UUID {
	return l.id
}

func (l Listener) Options() map[string]string {
	return l.options
}

func (l Listener) Protocol() string {
	return l.proto
}

// ServerID updates the structure with the server ID the server uses
func (l Listener) ServerID(id uuid.UUID) {
	l.serverID = id
}

func (l Listener) Update(options map[string]string) {
	l.options = options
}
