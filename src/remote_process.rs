use std::ffi::{c_void, CStr, CString};

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32First, Process32Next, Thread32First, Thread32Next, MODULEENTRY32W, PROCESSENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::{PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD};
use windows::Win32::UI::WindowsAndMessaging::{GetGUIThreadInfo, GUITHREADINFO};

use crate::remote_allocator::RemoteAllocator;
use crate::remote_thread::RemoteThread;
use crate::utils::to_wide;


pub struct RemoteProcess {
    handle: HANDLE,
    pid: u32,
}

impl RemoteProcess {
    pub fn from_name(process_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let target = process_name.to_ascii_lowercase();
        let processes = unsafe {CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;
        let mut pe32 = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        unsafe { Process32First(processes, &mut pe32)? };
        while unsafe { Process32Next(processes, &mut pe32).is_ok() } {
            let exe_name = unsafe { CStr::from_ptr(pe32.szExeFile.as_ptr()) }
                .to_string_lossy()
                .to_ascii_lowercase();

            if exe_name == target {
                unsafe { CloseHandle(processes)? };
                return Self::from_pid(pe32.th32ProcessID);
            }
        }

        Err(format!("process '{}' not found", process_name).into())
    }

    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    fn from_pid(pid: u32) -> Result<Self, Box<dyn std::error::Error>> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
                false,
                pid
            )?
        };
        Ok(Self { handle, pid })
    }

    pub fn write_wide_string(&self, s: &str) -> Result<*mut c_void, Box<dyn std::error::Error>> {
        let mut wide = to_wide(s);
        if *wide.last().unwrap_or(&0) != 0u16 {
            wide.push(0); // null-terminate if not already
        }

        let size = wide.len() * std::mem::size_of::<u16>();
        let addr = self.alloc(size, false)?;
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(wide.as_ptr() as *const u8, size)
        };

        self.write(addr, bytes)?;
        Ok(addr)
    }

    fn find_module_base(&self, module_name: &str) -> Result<usize, Box<dyn std::error::Error>> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid) }?;
        let mut me32 = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        unsafe { Module32FirstW(snapshot, &mut me32)?; }
        while unsafe { Module32NextW(snapshot, &mut me32) }.is_ok() {
            let name = String::from_utf16_lossy(&me32.szModule)
                .trim_end_matches('\0')
                .to_lowercase();

            if name.contains(&module_name.to_lowercase()) {
                let base = me32.modBaseAddr as usize;
                unsafe { CloseHandle(snapshot)?; }
                return Ok(base);
            }
        }

        unsafe { CloseHandle(snapshot)?; }
        Err(format!("module '{}' not found in target", module_name).into())
    }

    pub fn get_remote_func_address(&self, module_name: &str, func_name: &str) -> Result<usize, Box<dyn std::error::Error>> {
        let module_wide = to_wide(module_name);
        let local_mod = unsafe { GetModuleHandleW(PCWSTR(module_wide.as_ptr()))? };

        let c_func = CString::new(func_name)?;
        let local_func = unsafe { GetProcAddress(local_mod, PCSTR(c_func.as_ptr() as _)) }
            .ok_or("local func not found")?;

        let local_base = local_mod.0 as usize;
        let local_func_addr = local_func as usize;
        let offset = local_func_addr.wrapping_sub(local_base);

        // find remote module base and apply offset
        let remote_base = self.find_module_base(module_name)?;
        Ok(remote_base.wrapping_add(offset))
    }

    pub fn get_remote_thread(&self, gui: bool) -> Result<RemoteThread, Box<dyn std::error::Error>> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }?;
        let mut te32 = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        unsafe { Thread32First(snapshot, &mut te32) }?;

        while unsafe { Thread32Next(snapshot, &mut te32) }.is_ok() {
            if te32.th32OwnerProcessID == self.pid {
                let thread_id = te32.th32ThreadID;
                if gui {
                    let mut info = GUITHREADINFO {
                        cbSize: std::mem::size_of::<GUITHREADINFO>() as u32,
                        ..Default::default()
                    };

                    if unsafe { GetGUIThreadInfo(thread_id, &mut info).is_err() } {
                        continue;
                    }
                }
                unsafe { CloseHandle(snapshot) }?;
                return RemoteThread::open(thread_id);
            }
        }
        Err("No thread found in target process".into())
    }
}

impl Drop for RemoteProcess {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.handle); }
    }
}