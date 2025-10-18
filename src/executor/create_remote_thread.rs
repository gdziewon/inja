use std::ffi::c_void;

use windows::Win32::{Foundation::CloseHandle, System::Threading::{CreateRemoteThread, WaitForSingleObject}};

use crate::remote_process::RemoteProcess;

use super::ExecutionMethod;

pub(super) struct CreateRemoteThreadExecutor;

impl ExecutionMethod for CreateRemoteThreadExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_mem_alloc: *mut c_void,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let thread = unsafe { // todo: use remotethread
            CreateRemoteThread(
                remote_process.handle(),
                None,
                0,
                Some(std::mem::transmute(inject_func_addr)),
                Some(dll_path_mem_alloc),
                0,
                None
            )
        }?;

        unsafe { WaitForSingleObject(thread, u32::MAX) };
        unsafe { CloseHandle(thread) }?;

        Ok(())
    }

}