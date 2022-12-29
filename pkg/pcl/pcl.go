package pcl

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GetCommandLine returns command line that given window was started with.
func GetCommandLine(handle windows.HWND) (string, error) {
	var pID, retLen uint32
	var pbi pbis

	if _, err := windows.GetWindowThreadProcessId(handle, &pID); err != nil {
		return "", fmt.Errorf("error: %w", err)
	}

	wHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pID)
	if err != nil || wHandle == windows.InvalidHandle || wHandle == 0 {
		return "", fmt.Errorf("error: %w", err)
	}

	defer func() { _ = windows.CloseHandle(wHandle) }()

	if err = windows.NtQueryInformationProcess(wHandle, 0, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), &retLen); err != nil {
		return "", fmt.Errorf("error: %w", err)
	}

	if err == nil && retLen != uint32(unsafe.Sizeof(pbi)) {
		return "", fmt.Errorf("error: short read pbi")
	}

	paramsOffset := 0x20 // params offset of PEB on 64bit architecture, it's 0x10 on 32bit
	pebSize := paramsOffset + 8
	peb := make([]byte, pebSize)

	var nRead uintptr

	if err = windows.ReadProcessMemory(wHandle, pbi.pba, (*byte)(unsafe.Pointer(&peb[0])), uintptr(len(peb)), &nRead); err != nil {
		return "", fmt.Errorf("error: %w", err)
	}

	paramsAddr := *(*uintptr)(unsafe.Pointer(&peb[paramsOffset]))
	paramsBuf := make([]byte, sizeOfRtlUserProcessParameters)

	if err = windows.ReadProcessMemory(wHandle, paramsAddr, (*byte)(unsafe.Pointer(&paramsBuf[0])), uintptr(len(paramsBuf)), &nRead); err != nil {
		return "", fmt.Errorf("error: %w", err)
	}

	params := *(*rtlupp)(unsafe.Pointer(&paramsBuf[0]))
	clBuff := make([]uint16, params.cl.length)

	if err = windows.ReadProcessMemory(wHandle, params.cl.buffer, (*byte)(unsafe.Pointer(&clBuff[0])), uintptr(len(clBuff)*2), &nRead); err != nil {
		return "", fmt.Errorf("error: %w", err)
	}

	return windows.UTF16ToString(clBuff), nil
}

type pbis struct {
	_   uintptr
	pba uintptr
	_   [2]uintptr
	_   uintptr
	_   uintptr
}

type rtlupp struct {
	_ [16]byte
	_ [5]uintptr
	_ utf16s
	_ uintptr
	_ utf16s
	_ utf16s

	cl utf16s
}

type utf16s struct {
	length    uint16
	maxLength uint16
	buffer    uintptr
}

const sizeOfRtlUserProcessParameters = unsafe.Sizeof(rtlupp{})
