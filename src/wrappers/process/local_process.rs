use windows::core::BOOL;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, IsWow64Process};

use crate::wrappers::HandleWrapper;

trait Process : HandleWrapper {}

pub struct LocalProcess {
    handle: HANDLE,
    pid: u32,
}

impl Process for LocalProcess {}

impl HandleWrapper for LocalProcess {
    type HandleType = HANDLE;

    fn handle(&self) -> Self::HandleType {
        self.handle
    }

    fn handle_mut(&mut self) -> &mut Self::HandleType {
        &mut self.handle
    }
}

impl LocalProcess {
    pub fn new() -> Self {
        Self { // these functions CANNOT fail; even if M$ tried to bug them :)
            handle: unsafe { GetCurrentProcess() },
            pid: unsafe { GetCurrentProcessId() },
        }
    }

    pub fn is_wow64(&self) -> Result<bool, Box<dyn::std::error::Error>> {
        let mut result: BOOL = BOOL(0); // needs to be initialized
        unsafe { IsWow64Process(self.handle, &mut result)?; };

        Ok(result.as_bool())
    }
}