use std::{ffi::{c_void}, ptr, time::Duration};

use dynasmrt::{dynasm, DynasmApi};
use windows::{Wdk::Foundation::OBJECT_ATTRIBUTES, Win32::{Foundation::{NTSTATUS}, System::Threading::{THREAD_ALL_ACCESS}}};

use crate::wrappers::{
    HandleWrapper as _, RemoteAllocator, RemoteModule, RemoteProcess, RemoteThread
};

use super::ExecutionMethod;

pub type NtCreateThreadEx = unsafe extern "system" fn(
    thread_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    process_handle: *mut c_void,
    start_routine: *mut c_void,
    argument: *mut c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    maximum_stack_size: usize,
    attribute_list: *mut c_void,
) -> NTSTATUS;


pub(super) struct NtCreateThreadExExecutor;

impl ExecutionMethod for NtCreateThreadExExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_malloc: *mut c_void,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ntdll = RemoteModule::new("ntdll.dll")?;
        let address = ntdll.get_func_addr("NtCreateThreadEx")?;
        let create_thread_ex_func = unsafe { core::mem::transmute::<*mut core::ffi::c_void, NtCreateThreadEx>(address as *mut _) };

        let mut remote_thread = RemoteThread::default();
        let thread_handle_ptr = &mut remote_thread.handle_mut().0 as *mut _;

        let process_handle_ptr = remote_process.handle().0 as *mut c_void;

                // 2. build shellcode
        let stub = build_shcode(
            dll_path_malloc as u64,
            inject_func_addr as u64,
        )?;

        // 3. alloc & write shellcode to remote proc
        let shcode_mem = remote_process.alloc(stub.len(), true)?;
        remote_process.write(shcode_mem, &stub)?;

        // let start_routine = inject_func_addr as *mut c_void;

        let ntstatus = unsafe {
            create_thread_ex_func(
            thread_handle_ptr,
            THREAD_ALL_ACCESS.0,
            ptr::null_mut(),
            process_handle_ptr,
            shcode_mem,
            std::ptr::null_mut(),
            // dll_path_malloc,
            0,
            0,
            0,
            0,
            ptr::null_mut(),
            )
        };

        if ntstatus.0 != 0 {
            return Err(format!("NtCreateThreadEx failed with NTSTATUS: {:#x}", ntstatus.0).into());
        }

        remote_thread.wait_until_active(Duration::from_millis(u32::MAX as u64))?;

        Ok(())
    }
}

fn build_shcode(
    dll_path_ptr: u64,
    inject_func_ptr: u64
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut ops: dynasmrt::Assembler<dynasmrt::x64::X64Relocation> = dynasmrt::x64::Assembler::new()?;

    dynasm!(ops
        ; .arch x64
        ; sub rsp, 0x20 // shadow space
        ; sub rsp, 0x8  // align stack to 16 bytes (because call later pushes 8 bytes)

        ; mov rcx, QWORD dll_path_ptr as i64
        ; mov rax, QWORD inject_func_ptr as i64
        ; call rax

        ; add rsp, 0x28

        ; ret
    );

    let buf = ops.finalize().unwrap();
    println!("{:#04X?}, length: {}", buf.to_vec(), buf.to_vec().len());
    Ok(buf.to_vec())
}