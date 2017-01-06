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
	//Payload *json.RawMessage    `json:"payload,omitempty"`
}

//JSON cmd.exe Payload MESSAGE TYPE: CmdPayload
type CmdPayload struct {
	Command	   string `json:"executable"`
	Parameters string `json:"parameters"`
	Job	   string `json:"job"`
}

//JSON System Information Payload
type SysInfo struct {
	UserName string `json:"username,omitempty"`
	UserGUID string `json:"userguid,omitempty"`
	HostName string `json:"hostname,omitempty"`
	Pid 	 int	`json:"pid,omitempty"`
}

//JSON Powershell Command Results
type PSResults struct {
	Job string `json:"job"`
	Result string `json:"result"`
}

//JSON Agent Control Commands
type AgentControl struct {
	Job	   string `json:"job"`
	Command string `json:"command"`
	Result string `json:"result"`
}