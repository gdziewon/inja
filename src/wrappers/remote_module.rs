use windows::{core::{PCWSTR, PCSTR}, Win32::{Foundation::HMODULE, System::LibraryLoader::{GetModuleHandleW, GetProcAddress}}};

use crate::{utils::to_wide, wrappers::HandleWrapper};

pub struct RemoteModule {
    hmodule: HMODULE,
}

impl HandleWrapper for RemoteModule {
    type HandleType = HMODULE;

    fn handle(&self) -> Self::HandleType {
        self.hmodule
    }

    fn handle_mut(&mut self) -> &mut Self::HandleType {
        &mut self.hmodule
    }

    fn into_handle(self) -> Self::HandleType {
        let h = self.hmodule;
        std::mem::forget(self);
        h
    }
}

impl RemoteModule {
    pub fn new(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let wide_name = to_wide(name);
        let hmodule = unsafe {
            GetModuleHandleW(PCWSTR(wide_name.as_ptr()))
        }?;

        Ok(RemoteModule { hmodule })
    }

    pub fn get_func_addr(&self, func_name: &str) -> Result<usize, Box<dyn std::error::Error>> {
        let func_name_cstr = std::ffi::CString::new(func_name)?;
        let address = unsafe {
            GetProcAddress(self.hmodule, PCSTR(func_name_cstr.as_ptr() as _))
        };

        address
        .map(|p| p as usize)
        .ok_or_else(|| format!("Function '{}' not found in module", func_name).into())
    }
}
