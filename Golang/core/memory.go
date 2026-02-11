package core

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	psapi    = syscall.NewLazyDLL("psapi.dll")

	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
	procReadProcessMemory        = kernel32.NewProc("ReadProcessMemory")
	procWriteProcessMemory       = kernel32.NewProc("WriteProcessMemory")
	procVirtualAllocEx           = kernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx            = kernel32.NewProc("VirtualFreeEx")
	procGetCurrentProcess        = kernel32.NewProc("GetCurrentProcess")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = kernel32.NewProc("Process32FirstW")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
	procEnumProcessModulesEx     = psapi.NewProc("EnumProcessModulesEx")
	procGetModuleBaseNameW       = psapi.NewProc("GetModuleBaseNameW")

	procOpenProcessToken         = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation      = advapi32.NewProc("GetTokenInformation")
	procAdjustTokenPrivileges    = advapi32.NewProc("AdjustTokenPrivileges")
)

// -- Constants -----------------------------------------------------------------

const (
	PROCESS_ACCESS = 0x1F0FFF // PROCESS_ALL_ACCESS

	MEM_COMMIT     = 0x1000
	MEM_RESERVE    = 0x2000
	MEM_RELEASE    = 0x8000
	PAGE_EXECUTE_READWRITE = 0x40

	TH32CS_SNAPPROCESS = 0x2
	MAX_PATH           = 260

	TOKEN_READ              = 0x20008
	TOKEN_QUERY             = 0x0008
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	SE_PRIVILEGE_ENABLED    = 0x00000002
	TokenPrivileges         = 3

	LIST_MODULES_ALL = 0x03
)

// -- Win32 structs -------------------------------------------------------------

type processEntry32W struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	CntThreads        uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [MAX_PATH]uint16
}

type luid struct {
	LowPart  uint32
	HighPart int32
}

type luidAndAttributes struct {
	Luid       luid
	Attributes uint32
}

// -- Privilege Escalation ------------------------------------------------------

func GetMaxPrivileges() bool {
	hProc, _, _ := procGetCurrentProcess.Call()

	var hToken uintptr
	ret, _, _ := procOpenProcessToken.Call(
		hProc,
		uintptr(TOKEN_READ|TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES),
		uintptr(unsafe.Pointer(&hToken)),
	)
	if ret == 0 {
		return false
	}
	defer procCloseHandle.Call(hToken)

	// First call to get required buffer size
	var needed uint32
	procGetTokenInformation.Call(
		hToken,
		uintptr(TokenPrivileges),
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if needed == 0 {
		return false
	}

	// Allocate buffer and get token info
	buf := make([]byte, needed)
	ret, _, _ = procGetTokenInformation.Call(
		hToken,
		uintptr(TokenPrivileges),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)
	if ret == 0 {
		return false
	}

	// Parse: first 4 bytes = PrivilegeCount, then array of LUID_AND_ATTRIBUTES
	count := binary.LittleEndian.Uint32(buf[0:4])
	const laSize = 12 // sizeof(LUID_AND_ATTRIBUTES) = 4+4+4
	offset := 4

	for i := uint32(0); i < count; i++ {
		// Set Attributes to SE_PRIVILEGE_ENABLED (bytes 8..11 of each entry)
		attrOffset := offset + int(i)*laSize + 8
		binary.LittleEndian.PutUint32(buf[attrOffset:attrOffset+4], SE_PRIVILEGE_ENABLED)
	}

	// Apply
	ret, _, _ = procAdjustTokenPrivileges.Call(
		hToken,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(needed),
		0,
		0,
	)
	return ret != 0
}

// -- Process helpers -----------------------------------------------------------

type ProcessInfo struct {
	Name      string
	PID       uint32
	Threads   uint32
}

func GetProcesses() []ProcessInfo {
	snap, _, _ := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snap == ^uintptr(0) { // INVALID_HANDLE_VALUE
		return nil
	}
	defer procCloseHandle.Call(snap)

	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))

	var procs []ProcessInfo
	ret, _, _ := procProcess32First.Call(snap, uintptr(unsafe.Pointer(&entry)))
	for ret != 0 {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		procs = append(procs, ProcessInfo{
			Name:    name,
			PID:     entry.ProcessID,
			Threads: entry.CntThreads,
		})
		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procProcess32Next.Call(snap, uintptr(unsafe.Pointer(&entry)))
	}
	return procs
}

// -- Memory wrapper ------------------------------------------------------------

type Memory struct {
	Handle      uintptr
	PID         uint32
	BaseAddr    uintptr
	ProcessName string
}

func NewMemory() *Memory {
	return &Memory{}
}

func (m *Memory) Attach(processName string) bool {
	procs := GetProcesses()
	for _, p := range procs {
		if strings.EqualFold(p.Name, processName) {
			m.PID = p.PID

			handle, _, _ := procOpenProcess.Call(
				uintptr(PROCESS_ACCESS),
				0,
				uintptr(p.PID),
			)
			if handle == 0 {
				Info(fmt.Sprintf("OpenProcess failed for '%s'.", processName))
				return false
			}
			m.Handle = handle
			m.ProcessName = processName

			// Get base address of the main module
			m.BaseAddr = m.getModuleBase(processName)

			Success(fmt.Sprintf("Attached to '%s' (PID %d)", processName, m.PID))
			if m.BaseAddr != 0 {
				Success(fmt.Sprintf("Base address: 0x%x", m.BaseAddr))
			}
			return true
		}
	}

	Info(fmt.Sprintf("Process '%s' not found.", processName))
	return false
}

func (m *Memory) getModuleBase(moduleName string) uintptr {
	var hMods [1024]uintptr
	var cbNeeded uint32

	ret, _, _ := procEnumProcessModulesEx.Call(
		m.Handle,
		uintptr(unsafe.Pointer(&hMods[0])),
		uintptr(unsafe.Sizeof(hMods)),
		uintptr(unsafe.Pointer(&cbNeeded)),
		LIST_MODULES_ALL,
	)
	if ret == 0 {
		return 0
	}

	count := cbNeeded / uint32(unsafe.Sizeof(hMods[0]))
	nameBuf := make([]uint16, MAX_PATH)

	for i := uint32(0); i < count; i++ {
		procGetModuleBaseNameW.Call(
			m.Handle,
			hMods[i],
			uintptr(unsafe.Pointer(&nameBuf[0])),
			MAX_PATH,
		)
		name := syscall.UTF16ToString(nameBuf)
		if strings.EqualFold(name, moduleName) {
			return hMods[i]
		}
	}
	return hMods[0] // fallback: first module is usually the exe
}

func (m *Memory) Detach() {
	if m.Handle != 0 {
		procCloseHandle.Call(m.Handle)
		Success(fmt.Sprintf("Detached from '%s' (PID %d)", m.ProcessName, m.PID))
		m.Handle = 0
		m.PID = 0
		m.BaseAddr = 0
		m.ProcessName = ""
	}
}

func (m *Memory) GetBaseAddress() uintptr {
	return m.BaseAddr
}

// -- Read (generic via Go generics) -------------------------------------------

func Read[T any](m *Memory, address uintptr) T {
	var val T
	size := unsafe.Sizeof(val)
	procReadProcessMemory.Call(
		m.Handle,
		address,
		uintptr(unsafe.Pointer(&val)),
		size,
		0,
	)
	return val
}

func (m *Memory) ReadBytes(address uintptr, size uint) []byte {
	buf := make([]byte, size)
	procReadProcessMemory.Call(
		m.Handle,
		address,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		0,
	)
	return buf
}

func (m *Memory) ReadString(address uintptr, maxLen uint) string {
	buf := m.ReadBytes(address, maxLen)
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

func (m *Memory) ReadPointer(address uintptr) uintptr {
	return Read[uintptr](m, address)
}

// Convenience typed reads
func (m *Memory) ReadInt32(address uintptr) int32     { return Read[int32](m, address) }
func (m *Memory) ReadUint32(address uintptr) uint32   { return Read[uint32](m, address) }
func (m *Memory) ReadInt16(address uintptr) int16     { return Read[int16](m, address) }
func (m *Memory) ReadUint16(address uintptr) uint16   { return Read[uint16](m, address) }
func (m *Memory) ReadInt64(address uintptr) int64     { return Read[int64](m, address) }
func (m *Memory) ReadUint64(address uintptr) uint64   { return Read[uint64](m, address) }
func (m *Memory) ReadFloat32(address uintptr) float32 { return Read[float32](m, address) }
func (m *Memory) ReadFloat64(address uintptr) float64 { return Read[float64](m, address) }
func (m *Memory) ReadBool(address uintptr) bool       { return Read[bool](m, address) }
func (m *Memory) ReadByte(address uintptr) byte       { return Read[byte](m, address) }

// -- Write (generic via Go generics) ------------------------------------------

func Write[T any](m *Memory, address uintptr, value T) bool {
	size := unsafe.Sizeof(value)
	ret, _, _ := procWriteProcessMemory.Call(
		m.Handle,
		address,
		uintptr(unsafe.Pointer(&value)),
		size,
		0,
	)
	return ret != 0
}

func (m *Memory) WriteBytes(address uintptr, data []byte) bool {
	if len(data) == 0 {
		return false
	}
	ret, _, _ := procWriteProcessMemory.Call(
		m.Handle,
		address,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0,
	)
	return ret != 0
}

func (m *Memory) WriteString(address uintptr, value string) bool {
	return m.WriteBytes(address, append([]byte(value), 0))
}

func (m *Memory) WritePointer(address uintptr, value uintptr) bool {
	return Write(m, address, value)
}

// Convenience typed writes
func (m *Memory) WriteInt32(address uintptr, value int32) bool     { return Write(m, address, value) }
func (m *Memory) WriteUint32(address uintptr, value uint32) bool   { return Write(m, address, value) }
func (m *Memory) WriteInt16(address uintptr, value int16) bool     { return Write(m, address, value) }
func (m *Memory) WriteUint16(address uintptr, value uint16) bool   { return Write(m, address, value) }
func (m *Memory) WriteInt64(address uintptr, value int64) bool     { return Write(m, address, value) }
func (m *Memory) WriteUint64(address uintptr, value uint64) bool   { return Write(m, address, value) }
func (m *Memory) WriteFloat32(address uintptr, value float32) bool { return Write(m, address, value) }
func (m *Memory) WriteFloat64(address uintptr, value float64) bool { return Write(m, address, value) }
func (m *Memory) WriteBool(address uintptr, value bool) bool       { return Write(m, address, value) }
func (m *Memory) WriteByte(address uintptr, value byte) bool       { return Write(m, address, value) }

// -- Memory allocation ---------------------------------------------------------

func (m *Memory) Allocate(size uint) uintptr {
	addr, _, _ := procVirtualAllocEx.Call(
		m.Handle,
		0,
		uintptr(size),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)
	return addr
}

func (m *Memory) Free(address uintptr) {
	procVirtualFreeEx.Call(m.Handle, address, 0, MEM_RELEASE)
}

// -- Helpers for the demo (format like Python hex output) ----------------------

func HexBytes(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		fmt.Fprintf(&sb, "%02x", b)
	}
	return sb.String()
}

func Float64Bits(f float64) uint64 {
	return math.Float64bits(f)
}
