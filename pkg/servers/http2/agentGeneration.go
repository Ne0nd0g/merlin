package http2

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"text/template"

	"github.com/Ne0nd0g/merlin/pkg/util"

	"github.com/gobuffalo/packr"
)

type agentConfig struct {
	URL,
	Protocol,
	Sleep,
	Goos,
	Cgo,
	Outfile,
	Goarch string
}

func (s *Server) GetAgentOptionStrings() func(string) []string {
	//can probably do reflect to make this easier to manage
	return func(string) []string { return []string{"URL", "Protocol", "Sleep", "Cgo", "Outfile"} }
}

func (s *Server) GenerateAgent() []byte {
	//Thanks to moloch-- and the rosie project for figuring out how to do the generation stuff mostly good https://github.com/moloch--/rosie
	codeStruct := agentConfig{}

	URL, err := s.GetOptionValue("URL")
	protocol, err := s.GetOptionValue("protocol")
	sleep, err := s.GetOptionValue("sleep")

	codeStruct.URL = "*/\"" + URL + "\"//"
	codeStruct.Protocol = "*/\"" + protocol + "\"//"
	codeStruct.Sleep = "*/" + sleep + "//"
	folder := filepath.Join("..", "..", "..", "data", "src", "agenttemplates") //this value is relative to the compiled file - so doesn't need to be relative to the _current_ directory. The content is included in the merlin server binary
	file := "agent.go"
	boxs, err := packr.NewBox(folder).MustString(file)
	if err != nil {
		fmt.Println(err)
		return []byte("")
	}
	code, err := template.New("goagent").Parse(boxs)
	if err != nil {
		fmt.Println(err)
		return []byte("")
	}

	var buf bytes.Buffer

	err = code.Execute(&buf, codeStruct)

	if err != nil {
		fmt.Println(err)
	}

	binDir, err := ioutil.TempDir("", "merlin-agent-build")

	if err != nil {
		fmt.Println(err)
	}
	workingDir := path.Join(binDir, "agent.go")

	message("info", fmt.Sprintf("Using working directory: %s", workingDir))
	codeFile, err := os.Create(workingDir)
	if err != nil {
		fmt.Println(err)
	}

	err = code.Execute(codeFile, codeStruct)

	if err != nil {
		fmt.Println(err)
	}

	cgo, err := s.GetOptionValue("Cgo")
	if err != nil {
		cgo = "0"
	}
	goos, err := s.GetOptionValue("Goos")
	if err != nil {
		goos = "windows"
	}
	goarch, err := s.GetOptionValue("Goarch")
	if err != nil {
		goarch = "amd64"
	}

	outfile, _ := s.GetOptionValue("Outfile")

	buildr := []string{"build"}
	if outfile != "" {
		buildr = append(buildr, "-o")
		buildr = append(buildr, outfile)
	}

	goroot := os.Getenv("GOROOT")
	gopath := os.Getenv("GOPATH")
	err = util.GoCmd(util.GoConfig{
		CGO:    cgo,
		GOOS:   goos,
		GOARCH: goarch,
		GOROOT: goroot,
		GOPATH: gopath,
	},
		binDir,
		buildr,
	)

	if err != nil {
		fmt.Println(err)
		return []byte{}
	}

	return []byte{}
}
