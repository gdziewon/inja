use std::{ffi::c_void, time::Duration};

use windows::Win32::System::Threading::CreateRemoteThread;

use crate::wrappers::{
    HandleWrapper as _, RemoteProcess, RemoteThread
};

use super::ExecutionMethod;

pub(super) struct CreateRemoteThreadExecutor;

impl ExecutionMethod for CreateRemoteThreadExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_mem_alloc: *mut c_void,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let remote_thread = RemoteThread::from(
            unsafe { // todo: use remotethread
            CreateRemoteThread(
                remote_process.handle(),
                None,
                0,
                Some(std::mem::transmute(inject_func_addr)),
                Some(dll_path_mem_alloc),
                0,
                None
            )
        }?);

        remote_thread.wait_until_active(Duration::from_millis(u32::MAX as u64))?;

        Ok(())
    }

}