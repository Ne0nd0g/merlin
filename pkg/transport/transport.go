package transport

import (
	"io"
)

type MerlinResponse struct {
	Body    io.Reader //[]byte
	BodyLen int64
}

type MerlinCommClient interface {
	Do(b io.Reader) (MerlinResponse, error)
}
