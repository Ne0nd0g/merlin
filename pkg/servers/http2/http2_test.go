package http2

import (
	"fmt"
	"testing"
)

func TestAgentGeneration(t *testing.T) {
	s := Server{}
	fmt.Println(s.genGolangAgent())
	t.Fail()
}
