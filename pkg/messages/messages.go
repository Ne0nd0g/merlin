//Merlin is a post-exploitation command and control framework.
//This file is part of Merlin.
//Copyright (C) 2017  Russel Van Tuyl

//Merlin is free software: you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.

//Merlin is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
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

//JSON Agent Information Payload
type AgentInfo struct {
	Version string 	`json:"version,omitempty"`
	Build string 	`json:"build,omitempty"`
	WaitTime string `json:"waittime,omitempty"`
	PaddingMax int 	`json:"paddingmax,omitempty"`
	MaxRetry int 	`json:"maxretry,omitempty"`
	FailedCheckin int	`json:"failedcheckin,omitempty"`
}