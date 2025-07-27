use core::ffi::c_void;
use std::ffi::CStr;
use std::u32;
use std::path::PathBuf;
use clap::Parser;

use windows::core::{s, w};

use windows::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::{
            ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next},
            Debug::WriteProcessMemory
        },
        Threading::{
            WaitForSingleObject, CreateRemoteThread, OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD
        },
        Memory::{VirtualAllocEx, MEM_RESERVE, MEM_COMMIT, PAGE_READWRITE},
        LibraryLoader::{GetModuleHandleW, GetProcAddress}
    },
};

#[derive(Parser, Debug)]
struct Args {
    dll_path: PathBuf,
    process_name: String
}

fn get_process_id(process_name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let processes = unsafe {CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;
    let mut entry = PROCESSENTRY32::default();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    unsafe {
        Process32First(processes, &mut entry)?;
        while Process32Next(processes, &mut entry).is_ok() {
            let exe_name: std::borrow::Cow<str> = CStr::from_ptr(entry.szExeFile.as_ptr()).to_string_lossy();
            if process_name == exe_name {
                CloseHandle(processes)?;
                return Ok(entry.th32ProcessID);
            }
        }
    }

    return Err(format!("Couldn't find the process with name {process_name}").into())
}

fn inject(dll_path: &PathBuf, process_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pid = get_process_id(process_name)?;

    if !dll_path.exists() {
        return Err("dll doesnt exist".into());
    }
    let dll_path = dll_path.to_str().unwrap();
    let dll_path_wide = to_wide(dll_path);
    let path_size_in_bytes = dll_path_wide.len() * 2;

    let handle = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
            false,
            pid
        )
    }?;

    let allocated_memory = unsafe {
        VirtualAllocEx(
            handle, 
            None, 
            path_size_in_bytes, 
            MEM_RESERVE | MEM_COMMIT, 
            PAGE_READWRITE
        )
    };

    if allocated_memory.is_null() {
        return Err("Allocation failed".into());
    }

    unsafe {
        WriteProcessMemory(
            handle,
            allocated_memory,
            dll_path_wide.as_ptr() as *const c_void,
            path_size_in_bytes,
            None
        )
    }?;

    let kernel32 = unsafe { GetModuleHandleW(w!("kernel32.dll")) }?;
    let addr = unsafe { GetProcAddress(kernel32, s!("LoadLibraryW")) }
        .ok_or("LoadLibraryW not found")?;

    let _thread = unsafe {
        CreateRemoteThread(
            handle, 
            None,
            0,
            Some(std::mem::transmute(addr)),
            Some(allocated_memory),
            0,
            None
        )
    }?;

    unsafe {
        WaitForSingleObject(handle, u32::MAX);
    }
    
    // unsafe {
    //     VirtualFreeEx(handle, allocated_memory, 0, MEM_RELEASE)?;
    //     CloseHandle(thread)?;
    //     CloseHandle(handle)?;
    // }

    return Ok(());
}

fn to_wide(str: &str) -> Vec<u16> {
    str.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() {
    let args = Args::parse();
    inject(&args.dll_path, &args.process_name).unwrap();
}
