// +build windows

package agent

import (
	"bytes"
	"testing"
)

func TestGetProcess(t *testing.T) {
	// Ensure process that definitely exists returns a value
	lsassPid, _, err := getProccess("lsass.exe", 0)
	if lsassPid == 0 || err != nil {
		t.Error("Couldn't find lsass.exe")
	}
	// Ensure process that definitely doesn't exist returns a 0 value
	_, garbagePid, err := getProccess("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.exe")
	if garbagePid != 0 || err == nil {
		t.Error("Got a non zero return for a garbage process")
	}
}

func TestMinidump(t *testing.T) {

	// Check a good minidump works
	md, err := miniDump("", "go.exe", 0)
	byts := md.FileContent
	if err != nil {
		t.Error("Failed minidump on known process (possible false positive if run in non-windows environment somehow):", err)
	}
	if bytes.Compare(byts[:4], []byte("MDMP")) != 0 {
		t.Error("Invalid minidump file produced (based on file header)")
	}

	// Check a minidump on an unknown proc doesn't work
	_, err = miniDump("", "notarealprocess.exe", 0)
	if err == nil {
		t.Error("Found process when it shouldn't have...")
	}

	// Check a minidump providing a pid with blank string works
	pid, _, err := getProccess("go.exe", 0)
	md, err = miniDump("", "", pid)
	byts = md.FileContent
	if err != nil || len(byts) == 0 {
		t.Error("Minidump using pid failed")
	}

	// Verify proc name matches
	if md.ProcName != "go.exe" {
		t.Error("Minidump proc name does not match: ", "go.exe", md.ProcName)
	}

	// Check a minidump with a valid pid but invalid string works (pid should take priority)
	md, err = miniDump("", "notarealprocess.exe", pid)
	byts = md.FileContent
	if err != nil || len(byts) == 0 {
		t.Error("Minidump using valid pid and invalid proc name failed")
	}

	// Verify proc name matches
	if md.ProcName != "go.exe" {
		t.Error("Minidump proc name does not match: ", "go.exe", md.ProcName)
	}

	// Check a minidump with a valid proc name, but invalid pid fails
	md, err = miniDump("", "go.exe", 123456789)
	byts = md.FileContent
	if err == nil {
		t.Error("Minidump dumped a process even though provided pid was invalid")
	}

	// Check for non-existing path (dir)
	md, err = miniDump("C:\\thispathbetternot\\exist\\", "go.exe", 0)
	if err == nil {
		t.Error("Didn't get an error on non-existing path (check to make sure hte path doesn't actually exist)")
	}

	// Check for existing path (dir)
	md, err = miniDump("C:\\Windows\\temp\\", "go.exe", 0)
	if err != nil {
		t.Error("Got an error on existing path (check to make sure the path actually exists)")
		t.Error(err)
	}

	// Check for existing file
	md, err = miniDump("C:\\Windows\\System32\\calc.exe", "go.exe", 0)
	if err == nil {
		t.Error("Didn't get an error on existing file (check to make sure the path & file actually exist)")
	}

}
