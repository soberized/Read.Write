package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"time"

	"readwrite/core"
)

func main() {
	// -- Console setup ----------------------------------------------------------
	core.Clear()
	core.Title("read.write. | Golang")
	core.Banner("", "")

	// -- Escalate privileges immediately on startup -----------------------------
	core.Warn("Obtaining maximum privileges...")
	if !core.GetMaxPrivileges() {
		core.Info("Could not obtain privileges. Run as Administrator.")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	} else {
		core.Success("Obtained maximum privileges!")
	}

	// -- Demo – Notepad.exe -----------------------------------------------------
	cmd := exec.Command("notepad.exe")
	cmd.Start()
	time.Sleep(1 * time.Second)

	mem := core.NewMemory()
	if !mem.Attach("notepad.exe") {
		core.Info("Could not attach. Make sure to run this script as Administrator.")
		os.Exit(1)
	}

	base := mem.GetBaseAddress()

	// -- Read demo (PE header) --------------------------------------------------
	fmt.Println("\n --- READ demo (PE header) ---")

	mz := mem.ReadUint16(base)
	check := core.CHECK + " MZ"
	if mz != 0x5A4D {
		check = core.CROSS
	}
	core.Info(fmt.Sprintf("DOS magic  %s:%s 0x%04x  %s", core.Pink, core.Reset, mz, check))

	raw := mem.ReadBytes(base, 2)
	core.Info(fmt.Sprintf("Raw bytes  %s:%s %v", core.Pink, core.Reset, raw))

	peOff := mem.ReadInt32(base + 0x3C)
	core.Info(fmt.Sprintf("PE offset  %s:%s 0x%x", core.Pink, core.Reset, peOff))

	peSig := mem.ReadUint32(base + uintptr(peOff))
	peCheck := core.CHECK + " PE"
	if peSig != 0x4550 {
		peCheck = core.CROSS
	}
	core.Info(fmt.Sprintf("PE sig     %s:%s 0x%04x  %s", core.Pink, core.Reset, peSig, peCheck))

	// -- Write demo (allocated memory) ------------------------------------------
	fmt.Println("\n --- WRITE demo (allocated memory) ---")
	alloc := mem.Allocate(256)
	core.Info(fmt.Sprintf("Allocated 256 bytes %s@%s 0x%x", core.Pink, core.Reset, alloc))

	// int32
	mem.WriteInt32(alloc, 1337)
	core.Info(fmt.Sprintf("int     1337        %s>%s %d", core.Pink, core.Reset, mem.ReadInt32(alloc)))

	// float32
	mem.WriteFloat32(alloc+8, 3.14)
	core.Info(fmt.Sprintf("float   3.14        %s>%s %.2f", core.Pink, core.Reset, mem.ReadFloat32(alloc+8)))

	// float64 (double)
	mem.WriteFloat64(alloc+16, 2.718281828)
	core.Info(fmt.Sprintf("double  2.718..     %s>%s %.9f", core.Pink, core.Reset, mem.ReadFloat64(alloc+16)))

	// int64 (longlong)
	mem.WriteInt64(alloc+32, 0xDEADBEEFCAFE)
	core.Info(fmt.Sprintf("int64   0xDEAD..    %s>%s 0x%x", core.Pink, core.Reset, mem.ReadInt64(alloc+32)))

	// string
	mem.WriteString(alloc+64, "Hello from Golang!")
	core.Info(fmt.Sprintf("string              %s>%s '%s'", core.Pink, core.Reset, mem.ReadString(alloc+64, 18)))

	// bytes
	mem.WriteBytes(alloc+128, []byte{0xDE, 0xAD, 0xBE, 0xEF})
	core.Info(fmt.Sprintf("bytes               %s>%s %s", core.Pink, core.Reset, core.HexBytes(mem.ReadBytes(alloc+128, 4))))

	// bool
	mem.WriteBool(alloc+140, true)
	core.Info(fmt.Sprintf("bool    true        %s>%s %v", core.Pink, core.Reset, mem.ReadBool(alloc+140)))

	mem.Free(alloc)
	core.Warn("Freed allocated memory")

	mem.Detach()
	core.Success("Demo complete.")
}
