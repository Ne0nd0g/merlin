// Package suites allows callers to look up Kyber suites by name.
//
// Currently, only the "ed25519" suite is available with a constant
// time implementation and the other ones use variable time algorithms.
package suites

import (
	"errors"
	"strings"

	"go.dedis.ch/kyber/v3"
)

// Suite is the sum of all suites mix-ins in Kyber.
type Suite interface {
	kyber.Encoding
	kyber.Group
	kyber.HashFactory
	kyber.XOFFactory
	kyber.Random
}

var suites = map[string]Suite{}

var requireConstTime = false

// register is called by suites to make themselves known to Kyber.
//
func register(s Suite) {
	suites[strings.ToLower(s.String())] = s
}

// ErrUnknownSuite indicates that the suite was not one of the
// registered suites.
var ErrUnknownSuite = errors.New("unknown suite")

// Find looks up a suite by name.
func Find(name string) (Suite, error) {
	if s, ok := suites[strings.ToLower(name)]; ok {
		if requireConstTime && strings.ToLower(s.String()) != "ed25519" {
			return nil, errors.New("requested suite exists but is not implemented with constant time algorithms as required by suites.RequireConstantTime")
		}
		return s, nil
	}
	return nil, ErrUnknownSuite
}

// MustFind looks up a suite by name and panics if it is not found.
func MustFind(name string) Suite {
	s, err := Find(name)
	if err != nil {
		panic("Suite " + name + " not found.")
	}
	return s
}

// RequireConstantTime causes all future calls to Find and MustFind to only
// search for suites where the implementation is constant time.
// It should be called in an init() function for the main package
// of users of Kyber who need to be sure to avoid variable time implementations.
// Once constant time implementations are required, there is no way to
// turn it back off (by design).
//
// At this time, the only constant time crypto suite is "Ed25519".
func RequireConstantTime() {
	requireConstTime = true
}
