use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::OnceLock;
use windows::core::PCWSTR;
use windows::Win32::System::Diagnostics::Debug::{
    SymCleanup, SymFromNameW, SymInitializeW, SymLoadModuleExW, SymSetOptions, SYMBOL_INFOW, SYMOPT_AUTO_PUBLICS, SYMOPT_DEBUG, SYMOPT_DEFERRED_LOADS, SYMOPT_UNDNAME
};

use crate::symbols::loader::{SymbolLoader};
use crate::utils::to_wide;
use crate::wrappers::{HandleWrapper as _, RemoteModule, RemoteProcess};

static DBGHELP_GLOBAL_INIT: OnceLock<()> = OnceLock::new();
const MAX_SYM_NAME: usize = 2000;

pub struct SymbolHandler<'a> {
    process: &'a RemoteProcess,
    loader: SymbolLoader,
    loaded_modules: RefCell<HashSet<usize>>,
}

impl<'a> SymbolHandler<'a> {
    pub fn new(process: &'a RemoteProcess) -> Result<Self, Box<dyn std::error::Error>> {
        DBGHELP_GLOBAL_INIT.get_or_init(|| {
            unsafe { SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS | SYMOPT_DEBUG) };
        });
        
        let loader = SymbolLoader::new()?;
        let symbol_cache_path = to_wide(&loader.cache_dir().to_string_lossy());
        unsafe { SymInitializeW(process.handle(), PCWSTR(symbol_cache_path.as_ptr()), false) }?;

        Ok(Self { process, loader, loaded_modules: RefCell::new(HashSet::new()) })
    }

    fn load_symbols(
        &self,
        module: &RemoteModule,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.loaded_modules.borrow().contains(&module.base_addr()) {
            return Ok(());
        }

        self.loader.ensure_pdb_cached(module)?;

        let wide_module_path = to_wide(&module.path());
        let loaded_base = unsafe {
            SymLoadModuleExW(
                self.process.handle(),
                None,
                PCWSTR(wide_module_path.as_ptr()),
                None,
                module.base_addr() as u64,
                module.size() as u32,
                None,
                None,
            )
        };

        if loaded_base == 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(0) { // Ignore "already loaded"
                return Err(format!(
                    "SymLoadModuleExW failed for module '{}': {}",
                    module.path(), err
                ).into());
            }
        }

        self.loaded_modules.borrow_mut().insert(module.base_addr());

        Ok(())
    }

    pub fn get_symbol_address(
        &self,
        module: &RemoteModule,
        symbol_name: &str,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        self.load_symbols(module)?;

        let buffer_size = std::mem::size_of::<SYMBOL_INFOW>() + MAX_SYM_NAME * std::mem::size_of::<u16>();
        let mut symbol_buffer: Vec<u8> = vec![0; buffer_size];

        let symbol_info = unsafe { &mut *(symbol_buffer.as_mut_ptr() as *mut SYMBOL_INFOW) };
        symbol_info.SizeOfStruct = std::mem::size_of::<SYMBOL_INFOW>() as u32;
        symbol_info.MaxNameLen = MAX_SYM_NAME as u32;

        let wide_symbol_name = to_wide(symbol_name);
        unsafe { SymFromNameW(self.process.handle(), PCWSTR(wide_symbol_name.as_ptr()), symbol_info)?; }

        Ok(symbol_info.Address as usize)
    }
}

impl Drop for SymbolHandler<'_> {
    fn drop(&mut self) {
        let _ = unsafe { SymCleanup(self.process.handle()) };
    }
}