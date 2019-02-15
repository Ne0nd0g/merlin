package messages

import (
	"sync"

	"github.com/fatih/color"
)

var initialised bool
var mMutex *sync.Mutex

// Message is used to print a message to the command line
func Message(level string, message string) {
	if !initialised {
		mMutex = &sync.Mutex{}
		initialised = true
	}
	mMutex.Lock()
	defer mMutex.Unlock()
	switch level {
	case "info":
		color.Cyan("[i]" + message)
	case "note":
		color.Yellow("[-]" + message)
	case "warn":
		color.Red("[!]" + message)
	case "debug":
		color.Red("[DEBUG]" + message)
	case "success":
		color.Green("[+]" + message)
	default:
		color.Red("[_-_]Invalid message level: " + message)
	}
}
