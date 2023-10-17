package client

import uuid "github.com/satori/go.uuid"

type Repository interface {
	Add(client Client)
	Get(id uuid.UUID) (client Client, err error)
	GetAll() (clients []Client)
}
