mod core;

use crate::core::console::*;
use crate::core::memory::*;

use std::process::Command;
use std::thread;
use std::time::Duration;

fn main() {
    // -- Console setup ---------------------------------------------------------
    enable_ansi();
    clear();
    title("read.write. | Rust");
    banner("Rust", "soberized");

    // -- Escalate privileges immediately on startup ----------------------------
    warn("Obtaining maximum privileges...");
    if !get_max_privileges() {
        info("Could not obtain privileges. Run as Administrator.");
        let _ = std::io::stdin().read_line(&mut String::new());
    } else {
        success("Obtained maximum privileges!");
    }

    // =========================================================================
    // Demo – Notepad.exe
    // =========================================================================
    Command::new("notepad.exe")
        .spawn()
        .expect("failed to launch notepad");
    thread::sleep(Duration::from_secs(1));

    let mut mem = Memory::new();
    if !mem.attach("notepad.exe") {
        info("Could not attach. Make sure to run this script as Administrator.");
        std::process::exit(1);
    }

    let base = mem.get_base_address().unwrap();

    // -- Read demo (PE header) -------------------------------------------------
    println!("\n --- READ demo (PE header) ---");

    let mz = mem.read::<u16>(base).unwrap_or(0);
    let tag = if mz == 0x5A4D {
        format!("{} MZ", *CHECK)
    } else {
        format!("{}", *CROSS)
    };
    info(&format!("DOS magic  {PINK}:{RESET} {mz:#06x}  {tag}"));

    let raw = mem.read_bytes(base, 2).unwrap_or_default();
    info(&format!("Raw bytes  {PINK}:{RESET} {raw:?}"));

    let pe_off = mem.read::<i32>(base + 0x3C).unwrap_or(0);
    info(&format!("PE offset  {PINK}:{RESET} {pe_off:#x}"));

    let pe_sig = mem.read::<u32>(base + pe_off as usize).unwrap_or(0);
    let tag = if pe_sig == 0x4550 {
        format!("{} PE", *CHECK)
    } else {
        format!("{}", *CROSS)
    };
    info(&format!("PE sig     {PINK}:{RESET} {pe_sig:#06x}  {tag}"));

    // -- Write demo (allocated memory) -----------------------------------------
    println!("\n --- WRITE demo (allocated memory) ---");

    let alloc = mem.allocate(256).expect("allocation failed");
    info(&format!(
        "Allocated 256 bytes {PINK}@{RESET} {alloc:#x}"
    ));

    mem.write(alloc, &1337i32);
    info(&format!(
        "int     1337        {PINK}>{RESET} {}",
        mem.read::<i32>(alloc).unwrap()
    ));

    mem.write(alloc + 8, &3.14f32);
    info(&format!(
        "float   3.14        {PINK}>{RESET} {:.2}",
        mem.read::<f32>(alloc + 8).unwrap()
    ));

    mem.write(alloc + 16, &2.718281828f64);
    info(&format!(
        "double  2.718..     {PINK}>{RESET} {:.9}",
        mem.read::<f64>(alloc + 16).unwrap()
    ));

    mem.write(alloc + 32, &0xDEADBEEFCAFEi64);
    info(&format!(
        "int64   0xDEAD..    {PINK}>{RESET} {:#x}",
        mem.read::<i64>(alloc + 32).unwrap()
    ));

    mem.write_string(alloc + 64, "Hello from Rust!");
    info(&format!(
        "string              {PINK}>{RESET} '{}'",
        mem.read_string(alloc + 64, 16).unwrap()
    ));

    mem.write_bytes(alloc + 128, &[0xDE, 0xAD, 0xBE, 0xEF]);
    let bytes = mem.read_bytes(alloc + 128, 4).unwrap();
    info(&format!(
        "bytes               {PINK}>{RESET} {}",
        hex_str(&bytes)
    ));

    mem.write(alloc + 140, &true);
    info(&format!(
        "bool    True        {PINK}>{RESET} {}",
        mem.read::<bool>(alloc + 140).unwrap()
    ));

    mem.free(alloc);
    warn("Freed allocated memory");

    mem.detach();
    success("Demo complete.");
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
