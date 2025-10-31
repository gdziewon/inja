use std::time::Duration;

use windows::Win32::{Foundation::{CloseHandle, HANDLE, PAPCFUNC}, System::{Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_ALL_AMD64, CONTEXT_CONTROL_AMD64, CONTEXT_FULL_AMD64, CONTEXT_INTEGER_AMD64}, Threading::{GetThreadId, OpenThread, QueueUserAPC, ResumeThread, SuspendThread, THREAD_ACCESS_RIGHTS}}};

use crate::wrappers::HandleWrapper;

#[repr(align(16))]
pub struct Align16<T>(T);

impl<T> Align16<T> {
    pub fn get(&self) -> &T {
        &self.0
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

trait Thread : HandleWrapper {}

#[derive(Default)]
pub struct RemoteThread {
    handle: HANDLE,
    tid: u32,
    suspended: bool,
}

impl Thread for RemoteThread {}

impl From<HANDLE> for RemoteThread {
    fn from(handle: HANDLE) -> Self {
        let tid = unsafe { GetThreadId(handle) };
        Self {
            handle,
            tid,
            suspended: false,
        }
    }
}

impl HandleWrapper for RemoteThread {
    type HandleType = HANDLE;

    fn handle(&self) -> Self::HandleType {
        self.handle
    }

    fn handle_mut(&mut self) -> &mut Self::HandleType {
        &mut self.handle
    }
}

impl RemoteThread {
    pub fn open(tid: u32, desired_access: THREAD_ACCESS_RIGHTS) -> Result<Self, Box<dyn std::error::Error>> {
        let handle = unsafe { OpenThread(desired_access, false, tid) }?;
        Ok(Self {
            handle,
            tid,
            suspended: false,
        })
    }

    pub fn suspend(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.suspended {
            return Ok(());
        }
        if unsafe { SuspendThread(self.handle) } == u32::MAX {
            return Err("Failed to suspend thread".into());
        }
        self.suspended = true;
        Ok(())
    }

    pub fn resume(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.suspended {
            return Ok(());
        }
        if unsafe { ResumeThread(self.handle) } == u32::MAX {
            return Err("Failed to resume thread".into());
        }
        self.suspended = false;
        Ok(())
    }

    pub fn get_context(&self) -> Result<Align16<CONTEXT>, Box<dyn std::error::Error>> {
        let mut context = Align16(CONTEXT {
            ContextFlags: CONTEXT_ALL_AMD64 | CONTEXT_FULL_AMD64 | CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64,
            ..Default::default()
        });

        if unsafe { GetThreadContext(self.handle, &mut context.0) }.is_err() {
            return Err("GetThreadContext failed".into());
        }
        Ok(context)
    }

    pub fn set_context(&self, context: &Align16<CONTEXT>) -> Result<(), Box<dyn std::error::Error>> {
        if unsafe { SetThreadContext(self.handle, &context.0) }.is_err() {
            return Err("SetThreadContext failed".into());
        }
        Ok(())
    }

    pub fn wait_until_active(&self, timeout: Duration) -> Result<(), Box<dyn std::error::Error>> {
        let result = unsafe { windows::Win32::System::Threading::WaitForSingleObject(self.handle, timeout.as_millis() as u32) };
        match result {
            windows::Win32::Foundation::WAIT_OBJECT_0 => Ok(()),
            windows::Win32::Foundation::WAIT_TIMEOUT => Err("Wait timed out".into()),
            _ => Err("WaitForSingleObject failed".into()),
        }
    }

    pub fn queue_user_apc(&self, apc_fn_addr: PAPCFUNC, apc_param: usize) -> Result<(), Box<dyn std::error::Error>> {
        let result = unsafe { QueueUserAPC(apc_fn_addr, self.handle, apc_param) };
        if result == 0 {
            return Err(format!("QueueUserAPC failed: {}", std::io::Error::last_os_error()).into());
        }

        Ok(())
    }
}

impl Drop for RemoteThread {
    fn drop(&mut self) {
        if self.suspended {
            let _ = unsafe { ResumeThread(self.handle) };
            self.suspended = false;
        }
        unsafe { let _ = CloseHandle(self.handle); }
    }
}