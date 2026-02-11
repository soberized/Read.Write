package core

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"
)

// -- ANSI colours --------------------------------------------------------------

const (
	Pink  = "\033[38;5;213m"
	Reset = "\033[0m"
)

// -- Icons ---------------------------------------------------------------------

func Icon(symbol string) string {
	return fmt.Sprintf("[%s%s%s]", Pink, symbol, Reset)
}

var (
	INFO    = Icon("!")
	SUCCESS = Icon("+")
	WARN    = Icon("*")
	ARROW   = Icon(">")
	DASH    = Icon("-")
	DOT     = Icon(".")
	HASH    = Icon("#")
	AT      = Icon("@")
	CHECK   = Icon("/")
	CROSS   = Icon("X")
)

// -- Logging helpers -----------------------------------------------------------

func Log(msg string, prefix string) {
	fmt.Printf(" %s %s\n", prefix, msg)
}

func Info(msg string) {
	Log(msg, INFO)
}

func Success(msg string) {
	Log(msg, SUCCESS)
}

func Warn(msg string) {
	Log(msg, WARN)
}

// -- Console utilities ---------------------------------------------------------

func EnableAnsi() {
	if runtime.GOOS == "windows" {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		getStdHandle := kernel32.NewProc("GetStdHandle")
		getConsoleMode := kernel32.NewProc("GetConsoleMode")
		setConsoleMode := kernel32.NewProc("SetConsoleMode")

		const stdOutputHandle = ^uintptr(0) - 10 + 1 // STD_OUTPUT_HANDLE = -11
		handle, _, _ := getStdHandle.Call(stdOutputHandle)

		var mode uint32
		getConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
		mode |= 0x0004 // ENABLE_VIRTUAL_TERMINAL_PROCESSING
		setConsoleMode.Call(handle, uintptr(mode))
	}
}

func Clear() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		fmt.Print("\033[2J\033[H")
	}
}

func Title(text string) {
	if runtime.GOOS == "windows" {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		setConsoleTitle := kernel32.NewProc("SetConsoleTitleW")
		ptr, _ := syscall.UTF16PtrFromString(text)
		setConsoleTitle.Call(uintptr(unsafe.Pointer(ptr)))
	} else {
		fmt.Printf("\033]0;%s\007", text)
	}
}

func Banner(version string, author string) {
	if version == "" {
		version = "Golang"
	}
	if author == "" {
		author = "soberized"
	}
	fmt.Printf("\n read.%swrite.%s | Version %s@%s %s\n Developed by %s%s%s\n\n",
		Pink, Reset, Pink, Reset, version, Pink, author, Reset)
}

func init() {
	EnableAnsi()
}
