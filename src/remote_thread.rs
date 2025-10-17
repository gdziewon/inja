use windows::Win32::{Foundation::{CloseHandle, HANDLE}, System::{Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_ALL_AMD64, CONTEXT_CONTROL_AMD64, CONTEXT_FULL_AMD64, CONTEXT_INTEGER_AMD64}, Threading::{GetThreadId, OpenThread, ResumeThread, SuspendThread, THREAD_ALL_ACCESS}}};

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

pub struct RemoteThread {
    handle: HANDLE,
    tid: u32,
    suspended: bool,
}

impl RemoteThread {
    pub fn open(tid: u32) -> Result<Self, Box<dyn std::error::Error>> {
        let handle = unsafe { OpenThread(THREAD_ALL_ACCESS, false, tid) }?;
        Ok(Self {
            handle,
            tid,
            suspended: false,
        })
    }

    pub fn from_handle(handle: HANDLE) -> Self {
        let tid = unsafe { GetThreadId(handle) };
        Self {
            handle,
            tid,
            suspended: false,
        }
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

    pub fn into_raw(self) -> HANDLE {
        let h = self.handle;
        std::mem::forget(self);
        h
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