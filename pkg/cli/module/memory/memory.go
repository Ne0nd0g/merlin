package memory

import (
	"fmt"
	"github.com/Ne0nd0g/merlin/pkg/cli/module"
	uuid "github.com/satori/go.uuid"
	"strings"
	"sync"
)

type Repository struct {
	module map[uuid.UUID]*module.Module
	sync.Mutex
}

// repo is the in-memory database
var repo *Repository

func NewRepository() *Repository {
	if repo == nil {
		repo = &Repository{
			module: make(map[uuid.UUID]*module.Module),
		}
	}
	return repo
}

func (r *Repository) Add(m *module.Module) error {
	r.Lock()
	defer r.Unlock()
	r.module[m.ID()] = m
	return nil
}

func (r *Repository) Get(id uuid.UUID) (m *module.Module, err error) {
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

func (r *Repository) Reload(id uuid.UUID) (err error) {
	var m *module.Module
	// Get the module
	m, err = r.Get(id)
	if err != nil {
		return
	}
	m.UpdateOptions(m.OriginalOptions())
	err = r.Update(id, m)
	return
}

func (r *Repository) Update(id uuid.UUID, m *module.Module) (err error) {
	r.Lock()
	defer r.Unlock()
	_, ok := r.module[id]
	if !ok {
		err = fmt.Errorf("the module ID %s does not exist", id)
		return
	}
	r.module[id] = m
	return
}

func (r *Repository) UpdateOption(id uuid.UUID, key, value string) (err error) {
	var m *module.Module
	// Get the module
	m, err = r.Get(id)
	if err != nil {
		return
	}
	if strings.ToLower(key) == "agent" {
		if strings.ToLower(value) == "all" {
			value = "ffffffff-ffff-ffff-ffff-ffffffffffff"
		}
		if value != "" {
			// Validate the agent UUID
			_, err = uuid.FromString(value)
			if err != nil {
				err = fmt.Errorf("there was an error parsing '%s' as a UUID: %s", value, err)
				return
			}
		}
		m.UpdateAgent(value)
		err = r.Update(id, m)
		return
	}

	// Find the option
	options := m.Options()
	for i, option := range options {
		if option.Name == key {
			option.Value = value
			options[i] = option
			m.UpdateOptions(options)
			err = r.Update(id, m)
			return
		}
	}
	err = fmt.Errorf("the '%s' option does not exist for the %s module", key, m)
	return
}
