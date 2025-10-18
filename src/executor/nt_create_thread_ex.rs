use std::{ffi::{c_void, CString}, ptr};

use windows::{core::{w, PCSTR}, Wdk::Foundation::OBJECT_ATTRIBUTES, Win32::{Foundation::{CloseHandle, HANDLE, NTSTATUS}, System::{LibraryLoader::{GetModuleHandleW, GetProcAddress}, Threading::{WaitForSingleObject, THREAD_ALL_ACCESS}}}};

use crate::remote_process::RemoteProcess;

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
        dll_path_mem_alloc: *mut c_void,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ntdll = unsafe { GetModuleHandleW(w!("ntdll.dll"))? }; // todo: wrapper for modukles?
        let nt_func_name = CString::new("NtCreateThreadEx")?;
        let address = unsafe { GetProcAddress(ntdll, PCSTR(nt_func_name.as_ptr() as _)) };
        if address.is_none() {
            return Err("NtCreateThreadEx not found".into());
        }
        let create_thread_ex_func = unsafe { core::mem::transmute::<*mut core::ffi::c_void, NtCreateThreadEx>(address.unwrap() as *mut _) };
        let mut thread: HANDLE = HANDLE::default();
        let pthread: *mut *mut c_void = &mut thread.0;

        let ntstatus = unsafe { create_thread_ex_func(
            pthread,
            THREAD_ALL_ACCESS.0,
            ptr::null_mut(),
            remote_process.handle().0,
            std::mem::transmute(inject_func_addr),
            dll_path_mem_alloc,
            0,
            0,
            0,
            0,
            ptr::null_mut()
        ) };

        if ntstatus.0 != 0 {
            return Err(format!("NtCreateThreadEx failed with NTSTATUS: {:#x}", ntstatus.0).into());
        }

        unsafe { WaitForSingleObject(thread, u32::MAX) };
        unsafe { CloseHandle(thread) }?; // todo: use remote thread wrapper

        Ok(())
    }
}