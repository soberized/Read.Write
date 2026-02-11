use std::ffi::c_void;
use std::mem;

use windows::Win32::Foundation::*;
use windows::Win32::Security::*;
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::System::Threading::*;

use super::console::{PINK, RESET};

// ---------------------------------------------------------------------------
// Privilege escalation
// ---------------------------------------------------------------------------

pub fn get_max_privileges() -> bool {
    unsafe {
        let h_proc = GetCurrentProcess();
        let mut h_token = HANDLE::default();

        if OpenProcessToken(
            h_proc,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut h_token,
        )
        .is_err()
        {
            return false;
        }

        // First call — query required buffer size
        let mut needed: u32 = 0;
        let _ = GetTokenInformation(h_token, TokenPrivileges, None, 0, &mut needed);

        // Second call — fill buffer
        let mut buffer = vec![0u8; needed as usize];
        if GetTokenInformation(
            h_token,
            TokenPrivileges,
            Some(buffer.as_mut_ptr() as *mut c_void),
            needed,
            &mut needed,
        )
        .is_err()
        {
            let _ = CloseHandle(h_token);
            return false;
        }

        let tp = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);
        let count = tp.PrivilegeCount as usize;

        // Build new TOKEN_PRIVILEGES with every privilege enabled
        let size = mem::size_of::<u32>() + count * mem::size_of::<LUID_AND_ATTRIBUTES>();
        let mut new_buf = vec![0u8; size];
        let new_tp = &mut *(new_buf.as_mut_ptr() as *mut TOKEN_PRIVILEGES);
        new_tp.PrivilegeCount = count as u32;

        let src = std::slice::from_raw_parts(tp.Privileges.as_ptr(), count);
        let dst = std::slice::from_raw_parts_mut(new_tp.Privileges.as_mut_ptr(), count);

        for i in 0..count {
            dst[i].Luid = src[i].Luid;
            dst[i].Attributes = SE_PRIVILEGE_ENABLED;
        }

        let result = AdjustTokenPrivileges(
            h_token,
            false,
            Some(new_tp as *const TOKEN_PRIVILEGES),
            0,
            None,
            None,
        );

        let _ = CloseHandle(h_token);
        result.is_ok()
    }
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------

pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub threads: u32,
}

pub fn get_processes() -> Vec<ProcessInfo> {
    let mut result = Vec::new();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return result,
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name_len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);

                result.push(ProcessInfo {
                    name,
                    pid: entry.th32ProcessID,
                    threads: entry.cntThreads,
                });

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }
    result
}

// ---------------------------------------------------------------------------
// Memory wrapper
// ---------------------------------------------------------------------------

/// Usage:
/// ```ignore
/// let mut mem = Memory::new();
/// mem.attach("notepad.exe");
///
/// let val = mem.read::<i32>(addr);        // read<int>
/// mem.write(addr, &3.14f32);              // write<float>
///
/// let raw = mem.read_bytes(addr, 16);
/// mem.write_bytes(addr, &[0xDE, 0xAD]);
///
/// let s = mem.read_string(addr, 32);
/// mem.write_string(addr, "hello");
/// ```
pub struct Memory {
    handle: HANDLE,
    pid: u32,
    base_addr: Option<usize>,
    process_name: Option<String>,
}

impl Memory {
    pub fn new() -> Self {
        Self {
            handle: HANDLE::default(),
            pid: 0,
            base_addr: None,
            process_name: None,
        }
    }

    // -- attach / detach ---------------------------------------------------

    pub fn attach(&mut self, process_name: &str) -> bool {
        for proc in get_processes() {
            if proc.name == process_name {
                self.pid = proc.pid;
                unsafe {
                    self.handle = match OpenProcess(PROCESS_ALL_ACCESS, false, self.pid) {
                        Ok(h) => h,
                        Err(_) => return false,
                    };
                }
                self.process_name = Some(process_name.to_string());
                self.base_addr = self.find_module_base(process_name);

                println!(
                    " [{PINK}+{RESET}] Attached to '{process_name}' (PID {})",
                    self.pid
                );
                if let Some(base) = self.base_addr {
                    println!(" [{PINK}+{RESET}] Base address: {base:#x}");
                }
                return true;
            }
        }
        println!(" [{PINK}!{RESET}] Process '{process_name}' not found.");
        false
    }

    pub fn detach(&mut self) {
        if !self.handle.is_invalid() && self.handle != HANDLE::default() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
        if let Some(name) = &self.process_name {
            println!(
                " [{PINK}+{RESET}] Detached from '{name}' (PID {})",
                self.pid
            );
        }
        self.handle = HANDLE::default();
        self.pid = 0;
        self.base_addr = None;
        self.process_name = None;
    }

    pub fn get_base_address(&self) -> Option<usize> {
        self.base_addr
    }

    // -- generic read / write ---------------------------------------------

    pub fn read<T: Copy>(&self, address: usize) -> Option<T> {
        unsafe {
            let mut buffer: T = mem::zeroed();
            let mut bytes_read = 0usize;
            ReadProcessMemory(
                self.handle,
                address as *const c_void,
                &mut buffer as *mut T as *mut c_void,
                mem::size_of::<T>(),
                Some(&mut bytes_read),
            )
            .ok()
            .map(|_| buffer)
        }
    }

    pub fn write<T: Copy>(&self, address: usize, value: &T) -> bool {
        unsafe {
            let mut bytes_written = 0usize;
            WriteProcessMemory(
                self.handle,
                address as *const c_void,
                value as *const T as *const c_void,
                mem::size_of::<T>(),
                Some(&mut bytes_written),
            )
            .is_ok()
        }
    }

    // -- bytes ------------------------------------------------------------

    pub fn read_bytes(&self, address: usize, size: usize) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        unsafe {
            let mut bytes_read = 0usize;
            ReadProcessMemory(
                self.handle,
                address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                Some(&mut bytes_read),
            )
            .ok()
            .map(|_| buffer)
        }
    }

    pub fn write_bytes(&self, address: usize, data: &[u8]) -> bool {
        unsafe {
            let mut bytes_written = 0usize;
            WriteProcessMemory(
                self.handle,
                address as *const c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                Some(&mut bytes_written),
            )
            .is_ok()
        }
    }

    // -- string -----------------------------------------------------------

    pub fn read_string(&self, address: usize, max_len: usize) -> Option<String> {
        self.read_bytes(address, max_len).map(|bytes| {
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..end]).into_owned()
        })
    }

    pub fn write_string(&self, address: usize, s: &str) -> bool {
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0); // null terminator
        self.write_bytes(address, &bytes)
    }

    // -- pointer ----------------------------------------------------------

    pub fn read_ptr(&self, address: usize) -> Option<usize> {
        self.read::<u64>(address).map(|v| v as usize)
    }

    pub fn write_ptr(&self, address: usize, value: usize) -> bool {
        self.write(address, &(value as u64))
    }

    // -- allocation -------------------------------------------------------

    pub fn allocate(&self, size: usize) -> Option<usize> {
        unsafe {
            let addr = VirtualAllocEx(
                self.handle,
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if addr.is_null() {
                None
            } else {
                Some(addr as usize)
            }
        }
    }

    pub fn free(&self, address: usize) {
        unsafe {
            let _ = VirtualFreeEx(self.handle, address as *mut c_void, 0, MEM_RELEASE);
        }
    }

    // -- internal helpers -------------------------------------------------

    fn find_module_base(&self, name: &str) -> Option<usize> {
        unsafe {
            let mut modules = [HMODULE::default(); 1024];
            let mut needed: u32 = 0;

            if EnumProcessModulesEx(
                self.handle,
                modules.as_mut_ptr(),
                (modules.len() * mem::size_of::<HMODULE>()) as u32,
                &mut needed,
                LIST_MODULES_ALL,
            )
            .is_err()
            {
                return None;
            }

            let count = needed as usize / mem::size_of::<HMODULE>();
            for i in 0..count {
                let mut buf = [0u16; 260];
                let len = GetModuleBaseNameW(self.handle, modules[i], &mut buf);
                if len == 0 {
                    continue;
                }
                let mod_name = String::from_utf16_lossy(&buf[..len as usize]);
                if mod_name.eq_ignore_ascii_case(name) {
                    return Some(modules[i].0 as usize);
                }
            }
        }
        None
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        if !self.handle.is_invalid() && self.handle != HANDLE::default() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
            self.handle = HANDLE::default();
        }
    }
}
