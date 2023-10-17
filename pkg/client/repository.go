package client

import "github.com/google/uuid"

type Repository interface {
	Add(client Client)
	Get(id uuid.UUID) (client Client, err error)
	GetAll() (clients []Client)
}
