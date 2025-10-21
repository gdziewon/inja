use std::ffi::{c_void, CStr, CString};

use windows::core::{BOOL, PCSTR, PCWSTR};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, LPARAM};
use windows::Win32::System::Diagnostics::Debug::{FlushInstructionCache, ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32First, Process32Next, Thread32First, Thread32Next, MODULEENTRY32W, PROCESSENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, THREAD_ALL_ACCESS};
use windows::Win32::System::Threading::{PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD};
use windows::Win32::UI::WindowsAndMessaging::EnumWindows;
use super::RemoteAllocator;
use crate::wrappers::remote_thread::RemoteThread;
use crate::utils::to_wide;
use crate::wrappers::remote_window::RemoteWindow;
use crate::wrappers::HandleWrapper;

pub struct EnumWindowsData {
    target_pid: u32,
    windows: Vec<RemoteWindow>,
}

pub struct RemoteProcess {
    handle: HANDLE,
    pid: u32,
    thread_ids: Vec<u32>,
}

impl HandleWrapper for RemoteProcess {
    type HandleType = HANDLE;

    fn handle(&self) -> Self::HandleType {
        self.handle
    }

    fn handle_mut(&mut self) -> &mut Self::HandleType {
        &mut self.handle
    }

    fn into_handle(self) -> Self::HandleType {
        let h = self.handle;
        std::mem::forget(self);
        h
    }
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

    pub fn pid(&self) -> u32 {
        self.pid
    }
    
    fn from_pid(pid: u32) -> Result<Self, Box<dyn std::error::Error>> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
                false,
                pid
            )?
        };
        Ok(Self { handle, pid, thread_ids: Vec::new() })
    }
    
    pub fn thread_ids(&self) -> &Vec<u32> {
        &self.thread_ids
    }

    pub fn get_thread_ids(&self) -> Result<Vec<u32>, Box<dyn std::error::Error>> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }?;
        let mut te32 = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        unsafe { Thread32First(snapshot, &mut te32) }?;

        let mut thread_ids = Vec::new();
        while unsafe { Thread32Next(snapshot, &mut te32) }.is_ok() {
            if te32.th32OwnerProcessID == self.pid {
                thread_ids.push(te32.th32ThreadID);
            }
        }
        unsafe { CloseHandle(snapshot)?; }
        
        println!("For pid = {}; found thread id(s): {:?}", self.pid(), thread_ids);
        Ok(thread_ids)
    }

    pub fn get_windows(&self) -> Result<Vec<RemoteWindow>, Box<dyn std::error::Error>> {
        let mut enum_windows_data = EnumWindowsData {
            target_pid: self.pid,
            windows: Vec::new(),
        };

        unsafe {
            EnumWindows(Some(Self::enum_windows_callback), LPARAM(&mut enum_windows_data as *mut _ as isize))?;
        }

        Ok(enum_windows_data.windows)
    }

    // SAFETY: Caller must ensure that the lparam points to a valid EnumWindowsData
    unsafe extern "system" fn enum_windows_callback(
        hwnd: HWND,
        lparam: LPARAM
    ) -> BOOL {
        let data = unsafe { &mut *(lparam.0 as *mut EnumWindowsData) };

        let window = RemoteWindow::from_handle(hwnd);
        if window.is_err() {
            return BOOL(1);
        }

        let window = window.unwrap();
        if window.pid() != data.target_pid || !window.is_visible() {
            return BOOL(1);
        }

        data.windows.push(window);
        BOOL(1)
    }

    pub fn query_info<T>(&self, info_class: PROCESSINFOCLASS) -> Result<T, Box<dyn std::error::Error>> {
        let mut buffer: T = unsafe { std::mem::zeroed() }; // todo: look into this func
        let mut return_length: u32 = 0;

        let status = unsafe {
            NtQueryInformationProcess(
                self.handle(),
                info_class,
                &mut buffer as *mut _ as *mut c_void,
                std::mem::size_of::<T>() as u32,
                &mut return_length,
            )
        };

        if status.is_err() {
            return Err(format!("NtQueryInformationProcess failed: {:?}", status).into());
        }

        Ok(buffer)
    }

    pub fn read_memory(&self, addr: *const c_void, size: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buffer = vec![0u8; size];
        unsafe {
            ReadProcessMemory(
                self.handle(),
                addr as *mut c_void,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                None,
            )
        }?;
        Ok(buffer)
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

    pub fn find_module_base(&self, module_name: &str) -> Result<usize, Box<dyn std::error::Error>> { // todo: refactor
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
        let module_wide = to_wide(module_name); // todo: refactor
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

    pub fn get_remote_thread(&self) -> Result<RemoteThread, Box<dyn std::error::Error>> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }?;
        let mut te32 = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        unsafe { Thread32First(snapshot, &mut te32) }?;

        while unsafe { Thread32Next(snapshot, &mut te32) }.is_ok() {
            if te32.th32OwnerProcessID == self.pid {
                let thread_id: u32 = te32.th32ThreadID;
                unsafe { CloseHandle(snapshot) }?;
                return RemoteThread::open(thread_id, THREAD_ALL_ACCESS); // todo: pick right thread?
            }
        }
        Err("No thread found in target process".into())
    }

    pub fn free_library(&self, lib_mod_handle: usize) -> Result<(), Box<dyn std::error::Error>> { // todo: fix/refactor this is for unloading DLLs
        let free_library_addr = self.get_remote_func_address("kernel32.dll", "FreeLibrary")?;
        let remote_thread = RemoteThread::from(
            unsafe { 
                CreateRemoteThread(
                    self.handle,
                    None,
                    0,
                    Some(std::mem::transmute(free_library_addr)),
                    Some(lib_mod_handle as *const c_void),
                    0,
                    None    
            )}
        ?);

        remote_thread.wait_until_active(std::time::Duration::from_millis(u32::MAX as u64))?;

        Ok(())
    }
}

impl RemoteAllocator for RemoteProcess {
    fn alloc(&self, size: usize, exec: bool) -> Result<*mut c_void, Box<dyn std::error::Error>> {
        let prot = if exec { PAGE_EXECUTE_READWRITE } else { PAGE_READWRITE };
        let addr = unsafe {
            VirtualAllocEx(
                self.handle(),
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                prot,
            )
        };
        if addr.is_null() {
            return Err("Failed to allocate memory".into());
        }
        Ok(addr)
    }

    fn write(&self, addr: *mut c_void, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            WriteProcessMemory(
                self.handle(),
                addr,
                data.as_ptr() as *const c_void,
                data.len(),
                None
            )
        }?;
        Ok(())
    }

    fn flush_icache(&self, addr: *const c_void, size: usize) -> Result<(), Box<dyn std::error::Error>> {
        unsafe { FlushInstructionCache(self.handle(), Some(addr), size) }?;
        Ok(())
    }
}

impl Drop for RemoteProcess {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.handle); }
    }
}