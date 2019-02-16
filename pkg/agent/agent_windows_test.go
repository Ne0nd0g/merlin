// +build windows

package agent

import (
	"bytes"
	"testing"
)

func TestGetPrcID(t *testing.T) {
	//ensure proces that definitely exists returns a value
	lsassPid := getProcID("lsass.exe")
	if lsassPid == 0 {
		t.Error("Couldn't find lsass.exe")
	}
	//ensure process that definitely doesn't exist returns a 0 value
	garbagePid := getProcID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.exe")
	if garbagePid != 0 {
		t.Error("Got a non zero return for a garbage process")
	}
}

func TestMinidump(t *testing.T) {

	//check a good minidump works
	md, err := miniDump("", "go.exe", 0)
	byts := md.FileContent
	if err != nil {
		t.Error("Failed minidump on known process (possible false positive if run in non-windows environment somehow):", err)
	}
	if bytes.Compare(byts[:4], []byte("MDMP")) != 0 {
		t.Error("Invalid minidump file produced (based on file header)")
	}

	//check a minidump on an unknown proc doesn't work
	_, err = miniDump("", "notarealprocess.exe", 0)
	if err == nil {
		t.Error("Found process when it shouldn't have...")
	}

	//check a minidump providing a pid with blank string works
	pid, err := getProcID("go.exe")
	md, err = miniDump("", "", pid)
	byts = md.FileContent
	if err != nil || len(byts) == 0 {
		t.Error("Minidump using pid failed")
	}
	//verify proc name matches
	if md.ProcName != "go.exe" {
		t.Error("Minidump proc name does not match: ", "go.exe", md.ProcName)
	}

	//check a minidump with a valid pid but invalid string works (pid should take priority)
	md, err = miniDump("", "notarealprocess.exe", pid)
	byts = md.FileContent
	if err != nil || len(byts) == 0 {
		t.Error("Minidump using valid pid and invalid proc name failed")
	}
	//verify proc name matches
	if md.ProcName != "go.exe" {
		t.Error("Minidump proc name does not match: ", "go.exe", md.ProcName)
	}

	//check a minidump with a valid proc name, but invalid pid fails
	md, err = miniDump("", "go.exe", 123456789)
	byts = md.FileContent
	if err == nil {
		t.Error("Minidump dumped a process even though provided pid was invalid")
	}

}
