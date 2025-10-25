use std::time::Duration;

use windows::Win32::System::Threading::CreateRemoteThread;

use crate::wrappers::{
    AllocatedMemory, HandleWrapper as _, RemoteProcess, RemoteThread
};

use super::ExecutionMethod;

type CreateRemoteThreadFunc = unsafe extern "system" fn(*mut std::ffi::c_void) -> u32;

pub(super) struct CreateRemoteThreadExecutor;

impl ExecutionMethod for CreateRemoteThreadExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_mem_alloc: &AllocatedMemory,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let injecton_func: CreateRemoteThreadFunc = unsafe { std::mem::transmute(inject_func_addr) };

        let remote_thread = RemoteThread::from(
            unsafe {
                CreateRemoteThread(
                    remote_process.handle(),
                    None,
                    0,
                    Some(injecton_func),
                    Some(dll_path_mem_alloc.as_ptr()),
                    0,
                    None
                )
            }?
        );

        remote_thread.wait_until_active(Duration::from_millis(u32::MAX as u64))?;

        Ok(())
    }

}