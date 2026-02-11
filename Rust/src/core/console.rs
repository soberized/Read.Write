use std::sync::LazyLock;
use windows::core::PCWSTR;
use windows::Win32::System::Console::*;

// -- ANSI -------------------------------------------------------------------

pub const PINK: &str = "\x1b[38;5;213m";
pub const RESET: &str = "\x1b[0m";

// -- Icons ------------------------------------------------------------------

pub fn icon(symbol: &str) -> String {
    format!("[{PINK}{symbol}{RESET}]")
}

pub static INFO:    LazyLock<String> = LazyLock::new(|| icon("!"));
pub static SUCCESS: LazyLock<String> = LazyLock::new(|| icon("+"));
pub static WARN:    LazyLock<String> = LazyLock::new(|| icon("*"));
pub static ARROW:   LazyLock<String> = LazyLock::new(|| icon(">"));
pub static DASH:    LazyLock<String> = LazyLock::new(|| icon("-"));
pub static DOT:     LazyLock<String> = LazyLock::new(|| icon("."));
pub static HASH:    LazyLock<String> = LazyLock::new(|| icon("#"));
pub static AT:      LazyLock<String> = LazyLock::new(|| icon("@"));
pub static CHECK:   LazyLock<String> = LazyLock::new(|| icon("/"));
pub static CROSS:   LazyLock<String> = LazyLock::new(|| icon("X"));

// -- Logging ----------------------------------------------------------------

pub fn log(msg: &str, prefix: &str) {
    println!(" {prefix} {msg}");
}

pub fn info(msg: &str) {
    log(msg, &INFO);
}

pub fn success(msg: &str) {
    log(msg, &SUCCESS);
}

pub fn warn(msg: &str) {
    log(msg, &WARN);
}

// -- Console ----------------------------------------------------------------

pub fn enable_ansi() {
    unsafe {
        let handle = match GetStdHandle(STD_OUTPUT_HANDLE) {
            Ok(h) => h,
            Err(_) => return,
        };
        if handle.is_invalid() {
            return;
        }
        let mut mode = CONSOLE_MODE::default();
        if GetConsoleMode(handle, &mut mode).is_ok() {
            let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

pub fn clear() {
    let _ = std::process::Command::new("cmd").args(["/c", "cls"]).status();
}

pub fn title(text: &str) {
    unsafe {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let _ = SetConsoleTitleW(PCWSTR(wide.as_ptr()));
    }
}

pub fn banner(version: &str, author: &str) {
    println!();
    println!(" read.{PINK}write.{RESET} | Version {PINK}@{RESET} {version}");
    println!(" Developed by {PINK}{author}{RESET}");
    println!();
}
