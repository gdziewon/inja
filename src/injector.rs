use std::{
    ffi::{c_void, CStr},
    path::PathBuf
};

use windows::core::{s, w};
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{
        Diagnostics::{
            ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next},
            Debug::WriteProcessMemory
        },
        Threading::{
            WaitForSingleObject, OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD
        },
        Memory::{VirtualAllocEx, MEM_RESERVE, MEM_COMMIT, PAGE_READWRITE},
        LibraryLoader::{GetModuleHandleW, GetProcAddress}
    },
};

use crate::{
    executor::{execute, ShellcodeExecution},
    utils::to_wide
};

fn get_process_id(process_name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let target = process_name.to_ascii_lowercase();
    let processes = unsafe {CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;
    let mut entry = PROCESSENTRY32::default();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    unsafe {
        Process32First(processes, &mut entry)?;
        while Process32Next(processes, &mut entry).is_ok() {
            
            let exe_name = CStr::from_ptr(entry.szExeFile.as_ptr())
                .to_string_lossy()
                .to_ascii_lowercase();

            if target == exe_name {
                CloseHandle(processes)?;
                return Ok(entry.th32ProcessID);
            }
        }
    }

    return Err(format!("Couldn't find the process with name {process_name}").into())
}

fn get_process_handle(process_name: &str) -> Result<HANDLE, Box<dyn std::error::Error>> {
    let pid = get_process_id(process_name)?;
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

fn alloc_dll(dll_path: &str, process_handle: HANDLE) -> Result<*mut c_void, Box<dyn std::error::Error>> {
    let dll_path_wide = to_wide(dll_path);
    let path_size_in_bytes = dll_path_wide.len() * 2;

    let dll_path_mem_alloc = unsafe {
        VirtualAllocEx(
            process_handle, 
            None, 
            path_size_in_bytes, 
            MEM_RESERVE | MEM_COMMIT, 
            PAGE_READWRITE
        )
    };

    if dll_path_mem_alloc.is_null() {
        return Err("Allocation failed".into());
    }

    unsafe {
        WriteProcessMemory(
            process_handle,
            dll_path_mem_alloc,
            dll_path_wide.as_ptr() as *const c_void,
            path_size_in_bytes,
            None
        )
    }?;

    Ok(dll_path_mem_alloc)
}

pub fn inject(dll_path: &PathBuf, process_name: &str, shellcode_execution_method: ShellcodeExecution) -> Result<(), Box<dyn std::error::Error>> {
    if !dll_path.exists() {
        return Err("dll doesnt exist".into());
    }

    let dll_str = dll_path
        .to_str()
        .ok_or_else(|| "Couldnt convert path to &str")?;

    let process_handle = get_process_handle(process_name)?;
    
    let dll_path_mem_alloc = alloc_dll(dll_str, process_handle)?;

    let kernel32 = unsafe { GetModuleHandleW(w!("kernel32.dll")) }?;
    let inject_func = unsafe { GetProcAddress(kernel32, s!("LoadLibraryW")) }
        .ok_or("LoadLibraryW not found")?;

    let thread_handle = execute(shellcode_execution_method, process_handle, inject_func, dll_path_mem_alloc)?;

    unsafe {
        WaitForSingleObject(thread_handle, u32::MAX);
    };

    Ok(())
}



// pub trait Injector {
//     fn inject(&self, process_handle: HANDLE, dll_path: &PathBuf) -> Result<bool, Box<dyn std::error::Error>>;
// }