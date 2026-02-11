import sys
sys.dont_write_bytecode = True  

from core import (
    Memory, get_max_privileges,
    pink, reset,
    INFO, SUCCESS, WARN, CHECK, CROSS,
    info, success, warn, log,
    clear, title, banner,
)
import os
import time

# -- Console setup --------------------------------------------------------------
clear()
title("read.write. | Python")
banner()

# -- Escalate privileges immediately on startup --------------------------------
warn("Obtaining maximum privileges...")
if not get_max_privileges():
    info("Could not obtain privileges. Run as Administrator.")
    input()
else:
    success("Obtained maximum privileges!")


# =============================================================================
# Demo – Notepad.exe
# =============================================================================
if __name__ == "__main__":
    os.startfile("notepad.exe")
    time.sleep(1)

    mem = Memory()
    if not mem.attach("notepad.exe"):
        info("Could not attach. Make sure to run this script as Administrator.")
        sys.exit(1)

    base = mem.get_base_address()

    # -- Read demo (PE header) --------------------------------------------------
    print(f"\n --- READ demo (PE header) ---")

    mz = mem.read(base, "ushort")
    info(f"DOS magic  {pink}:{reset} {mz:#06x}  {CHECK + ' MZ' if mz == 0x5A4D else CROSS}")

    raw = mem.read(base, "bytes", size=2)
    info(f"Raw bytes  {pink}:{reset} {raw}")

    pe_off = mem.read(base + 0x3C, "int")
    info(f"PE offset  {pink}:{reset} {pe_off:#x}")

    pe_sig = mem.read(base + pe_off, "uint")
    info(f"PE sig     {pink}:{reset} {pe_sig:#06x}  {CHECK + ' PE' if pe_sig == 0x4550 else CROSS}")

    # -- Write demo (allocated memory) ------------------------------------------
    print(f"\n --- WRITE demo (allocated memory) ---")
    alloc = mem.allocate(256)
    info(f"Allocated 256 bytes {pink}@{reset} {alloc:#x}")

    mem.write(alloc, 1337, "int")
    info(f"int     1337        {pink}>{reset} {mem.read(alloc, 'int')}")

    mem.write(alloc + 8, 3.14, "float")
    info(f"float   3.14        {pink}>{reset} {mem.read(alloc + 8, 'float'):.2f}")

    mem.write(alloc + 16, 2.718281828, "double")
    info(f"double  2.718..     {pink}>{reset} {mem.read(alloc + 16, 'double'):.9f}")

    mem.write(alloc + 32, 0xDEADBEEFCAFE, "longlong")
    info(f"int64   0xDEAD..    {pink}>{reset} {mem.read(alloc + 32, 'longlong'):#x}")

    mem.write(alloc + 64, "Hello from Python!", "str")
    info(f"string              {pink}>{reset} '{mem.read(alloc + 64, 'str', size=18)}'")

    mem.write(alloc + 128, b"\xDE\xAD\xBE\xEF", "bytes")
    info(f"bytes               {pink}>{reset} {mem.read(alloc + 128, 'bytes', size=4).hex()}")

    mem.write(alloc + 140, True, "bool")
    info(f"bool    True        {pink}>{reset} {mem.read(alloc + 140, 'bool')}")

    mem.free(alloc)
    warn("Freed allocated memory")

    mem.detach()
    success("Demo complete.")
