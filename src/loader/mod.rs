use std::ffi::c_void;

use crate::wrappers::RemoteProcess;

mod load_library;
mod ldr_load_dll;

use load_library::LoadLibraryLoader;
use ldr_load_dll::LdrLoadDllLoader;

#[derive(Debug)]
pub enum LoadStrategy {
    LoadLibrary, // GH uses LoadLibraryExW
    LdrLoadDll,

}

pub trait LoadMethod {
    fn build_sc0de(
        target_process: &RemoteProcess,
        dll_path_malloc: *mut c_void,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}

pub struct Loader<'a> {
    target_process: &'a RemoteProcess,
    dll_path_malloc: *mut c_void,
}

impl Loader<'_> {
    pub fn new(
        target_process: &RemoteProcess,
        dll_path_malloc: *mut c_void
    ) -> Loader {
        Loader {
            target_process,
            dll_path_malloc,
        }
    }

    pub fn build_sc0de(&self, dll_load_method: LoadStrategy) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        match dll_load_method {
            LoadStrategy::LoadLibrary => LoadLibraryLoader::build_sc0de(
                self.target_process,
                self.dll_path_malloc,
            ),
            LoadStrategy::LdrLoadDll => LdrLoadDllLoader::build_sc0de(
                self.target_process,
                self.dll_path_malloc,
            ),
        }
    }
}