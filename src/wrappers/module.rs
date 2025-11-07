use std::{ffi::CString, path::{Path, PathBuf}};

use clap::builder::Str;
use windows::{core::{PCWSTR, PCSTR}, Win32::{Foundation::HMODULE, System::LibraryLoader::{GetModuleHandleW, GetProcAddress}}};

use crate::{utils::to_wide, wrappers::HandleWrapper};

pub trait Module : HandleWrapper {
    fn get_func_addr(&self, func_name: &str) -> Result<usize, Box<dyn std::error::Error>>;
}

pub struct LocalModule {
    hmodule: HMODULE,
    base_addr: usize,
}

impl Module for LocalModule {
    fn get_func_addr(&self, func_name: &str) -> Result<usize, Box<dyn std::error::Error>> {
        let func_name_cstr = CString::new(func_name)?;
        let address = unsafe {
            GetProcAddress(self.hmodule, PCSTR(func_name_cstr.as_ptr() as _))
        };

        address
        .map(|p| p as usize)
        .ok_or_else(|| format!("Function '{func_name}' not found in module").into())
    }
}

impl From<HMODULE> for LocalModule {
    fn from(handle: HMODULE) -> Self {
        LocalModule { hmodule: handle, base_addr: handle.0 as usize }
    }
}

impl HandleWrapper for LocalModule {
    type HandleType = HMODULE;

    fn handle(&self) -> Self::HandleType {
        self.hmodule
    }

    fn handle_mut(&mut self) -> &mut Self::HandleType {
        &mut self.hmodule
    }
}

impl LocalModule {
    pub fn from_name(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let wide_name = to_wide(name);
        let hmodule = unsafe {
            GetModuleHandleW(PCWSTR(wide_name.as_ptr()))
        }?;

        Ok(LocalModule { hmodule, base_addr: hmodule.0 as usize })
    }

    pub fn base_addr(&self) -> usize {
        self.base_addr
    }
}

pub struct RemoteModule {
    name: String,
    hmodule: HMODULE,
    base_addr: usize,
    size: usize,
    path: String,
}

impl Module for RemoteModule {
    fn get_func_addr(&self, func_name: &str) -> Result<usize, Box<dyn std::error::Error>> {
        let local_module = LocalModule::from_name(&self.name)?;
        let local_func_addr = local_module.get_func_addr(func_name)?;

        let offset = local_func_addr.wrapping_sub(local_module.base_addr());

        Ok(self.base_addr.wrapping_add(offset))
    }
}

impl HandleWrapper for RemoteModule {
    type HandleType = HMODULE;

    fn handle(&self) -> Self::HandleType {
        self.hmodule
    }

    fn handle_mut(&mut self) -> &mut Self::HandleType {
        &mut self.hmodule
    }
}

impl RemoteModule {
    pub fn new(name: &str, hmodule: HMODULE, base_addr: usize, size: usize, path: &str) -> Self {
        RemoteModule { name: name.to_owned(), hmodule, base_addr, size, path: path.to_owned() }
    }

    pub fn base_addr(&self) -> usize {
        self.base_addr
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn path(&self) -> &String {
        &self.path
    }

    pub fn name(&self) -> &String {
        &self.name
    }
}