use std::{
    ffi::{c_void, CStr},
    path::PathBuf
};

use windows::{core::{s, w}, Win32::System::{Diagnostics::{Debug::WriteProcessMemory, ToolHelp::{Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32}}, Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE}}};
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{
        Diagnostics::{
            ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next},
        },
        Threading::{
            WaitForSingleObject, OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD
        },
        LibraryLoader::{GetModuleHandleW, GetProcAddress}
    },
};

use crate::{
    executor::{execute, ShellcodeExecution},
    utils::to_wide
};

pub struct Injector {
    handle: HANDLE,
    pid: u32,
}

impl Injector {
    pub fn new(process_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let pid = get_process_id(process_name)?;
        let handle = get_process_handle(pid)?;

        Ok(Injector { handle, pid })
    }

    pub fn inject(&self, dll_path: &PathBuf, shellcode_execution_method: ShellcodeExecution) -> Result<(), Box<dyn std::error::Error>> {
        if !dll_path.exists() {
            return Err("dll doesnt exist".into());
        }

        let dll_str = dll_path
            .to_str()
            .ok_or_else(|| "Couldnt convert path to &str")?;

        let remote_func_addr = self.get_remote_loadlibrary_address()?;
        let dll_path_mem_alloc = self.remote_write_dll_path(dll_str)?;

        let thread_handle = execute(shellcode_execution_method.clone(), self.handle, remote_func_addr, dll_path_mem_alloc)?;

        match shellcode_execution_method {
            ShellcodeExecution::ThreadHijacking => {
                unsafe { CloseHandle(thread_handle)?; }
            }
            _ => {
                unsafe { WaitForSingleObject(thread_handle, u32::MAX); }
                unsafe { CloseHandle(thread_handle)?; }
            }
        }

        Ok(())
    }

    fn get_remote_loadlibrary_address(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid) }?;
        let mut module_entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        
        unsafe { Module32FirstW(snapshot, &mut module_entry) }?;
        
        let mut kernel32_base = 0;
        loop {
            let module_name = String::from_utf16_lossy(&module_entry.szModule);
            if module_name.to_lowercase().contains("kernel32") {
                kernel32_base = module_entry.modBaseAddr as usize;
                break;
            }
            
            if unsafe { Module32NextW(snapshot, &mut module_entry) }.is_err() {
                break;
            }
        }
        
        unsafe { CloseHandle(snapshot) }?;
        
        if kernel32_base == 0 {
            return Err("Kernel32 not found in target process".into());
        }
        
        // get LoadLibraryW address in our process
        let local_kernel32 = unsafe { GetModuleHandleW(w!("kernel32.dll"))? };
        let local_loadlibrary = unsafe { GetProcAddress(local_kernel32, s!("LoadLibraryW")) }
            .ok_or("LoadLibraryW not found")?;
        
        // calculate offset and apply to target process
        let offset = local_loadlibrary as usize - local_kernel32.0 as usize;
        let remote_loadlibrary = kernel32_base + offset;
        
        Ok(remote_loadlibrary)
    }

    fn remote_write_dll_path(&self, dll_path: &str) -> Result<*mut c_void, Box<dyn std::error::Error>> {
        let dll_path_wide = to_wide(dll_path);
        let path_size_in_bytes = dll_path_wide.len() * 2;

        let dll_path_mem_alloc = unsafe {
            VirtualAllocEx(
                self.handle, 
                None, 
                path_size_in_bytes, 
                MEM_RESERVE | MEM_COMMIT, 
                PAGE_EXECUTE_READWRITE
            )
        };

        if dll_path_mem_alloc.is_null() {
            return Err("Allocation failed".into());
        }

        unsafe {
            WriteProcessMemory(
                self.handle,
                dll_path_mem_alloc,
                dll_path_wide.as_ptr() as *const c_void,
                path_size_in_bytes,
                None
            )
        }?;

        Ok(dll_path_mem_alloc)
    }
}

fn get_process_id(process_name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let target = process_name.to_ascii_lowercase();
    let processes = unsafe {CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;
    let mut process_entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    unsafe {
        Process32First(processes, &mut process_entry)?;
        while Process32Next(processes, &mut process_entry).is_ok() {
            
            let exe_name = CStr::from_ptr(process_entry.szExeFile.as_ptr())
                .to_string_lossy()
                .to_ascii_lowercase();

            if target == exe_name {
                CloseHandle(processes)?;
                return Ok(process_entry.th32ProcessID);
            }
        }
    }

    return Err(format!("Couldn't find the process with name {process_name}").into())
}

fn get_process_handle(pid: u32) -> Result<HANDLE, Box<dyn std::error::Error>> {
    unsafe {
        Ok(
            OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
            false,
            pid
            )?
        )
    }
}

