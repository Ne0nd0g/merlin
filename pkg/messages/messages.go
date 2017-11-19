package messages

import (
	"github.com/satori/go.uuid"
)

//JSON Object for Messages
type Base struct {
	Version float32   	`json:"version"`
	ID      uuid.UUID 	`json:"id"`
	Type    string    	`json:"type"`
	Payload interface{}    `json:"payload,omitempty"`
	Padding string		`json:"padding"`
}

//JSON Payload MESSAGE TYPE: CmdPayload
type CmdPayload struct {
	Command	   string `json:"executable"`
	Args string `json:"args"`
	Job	   string `json:"job"`
}

//JSON System Information Payload
type SysInfo struct {
	Platform string `json:"platform,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	UserName string `json:"username,omitempty"`
	UserGUID string `json:"userguid,omitempty"`
	HostName string `json:"hostname,omitempty"`
	Pid 	 int	`json:"pid,omitempty"`
}

//JSON Command Results
type CmdResults struct {
	Job string `json:"job"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Padding string `json:"padding"` //Padding to help evade detection
}

//JSON Agent Control Commands
type AgentControl struct {
	Job	   string 	`json:"job"`
	Command string 	`json:"command"`
	Args string		`json:"args,omitempty"`
	Result string 	`json:"result"`
}