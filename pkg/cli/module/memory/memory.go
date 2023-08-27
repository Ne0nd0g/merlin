package memory

import (
	"fmt"
	uuid "github.com/satori/go.uuid"
	"sync"

	"github.com/Ne0nd0g/merlin/pkg/modules"
)

type Repository struct {
	module map[uuid.UUID]modules.Module
	sync.Mutex
}

// repo is the in-memory database
var repo *Repository

func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{
			module: make(map[uuid.UUID]modules.Module),
		}
	}
	return repo
}

func (r *Repository) Add(m modules.Module) error {
	r.Lock()
	defer r.Unlock()
	r.module[m.ID()] = m
	return nil
}

func (r *Repository) Get(id uuid.UUID) (m modules.Module, err error) {
	r.Lock()
	defer r.Unlock()

	_, ok := r.module[id]
	if !ok {
		err = fmt.Errorf("the module ID %s does not exist", id)
		return
	}
	m = r.module[id]
	return
}

func (r *Repository) Update(id uuid.UUID, module modules.Module) (err error) {
	r.Lock()
	defer r.Unlock()
	_, ok := r.module[id]
	if !ok {
		err = fmt.Errorf("the module ID %s does not exist", id)
		return
	}
	r.module[id] = module
	return
}
