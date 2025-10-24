use std::ffi::{c_void, CStr, OsString};
use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStringExt as _;

use windows::core::BOOL;
use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, LPARAM};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use windows::Win32::System::Threading::{GetProcessId, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, THREAD_ALL_ACCESS};
use windows::Win32::System::Threading::{PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD};
use windows::Win32::UI::WindowsAndMessaging::EnumWindows;
use super::RemoteAllocator;
use crate::wrappers::memory::AllocatedMemory;
use crate::wrappers::module::RemoteModule;
use crate::wrappers::{ModuleSnapshot, ProcessSnapshot, RemoteThread, ThreadSnapshot};
use crate::utils::to_wide;
use crate::wrappers::window::RemoteWindow;
use crate::wrappers::HandleWrapper;

pub struct EnumWindowsData {
    target_pid: u32,
    windows: Vec<RemoteWindow>,
}

trait Process : HandleWrapper {}

pub struct RemoteProcess {
    handle: HANDLE,
    pid: u32,
}

impl Process for RemoteProcess {}

impl From<HANDLE> for RemoteProcess {
    fn from(handle: HANDLE) -> Self {
        let pid = unsafe { GetProcessId(handle) };
        Self { handle, pid }
    }
}

impl HandleWrapper for RemoteProcess {
    type HandleType = HANDLE;

    fn handle(&self) -> Self::HandleType {
        self.handle
    }

    fn handle_mut(&mut self) -> &mut Self::HandleType {
        &mut self.handle
    }
}

impl RemoteProcess {
    pub fn from_name(process_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut snapshot = ProcessSnapshot::create()?;

        let found_entry = snapshot.find(|pe32| {
            let exe_name = unsafe { CStr::from_ptr(pe32.szExeFile.as_ptr()) };
            
            exe_name.to_string_lossy().eq_ignore_ascii_case(process_name)
        });

        match found_entry {
            Some(pe32) => Self::from_pid(pe32.th32ProcessID),
            None => Err(format!("process '{}' not found", process_name).into()),
        }
    }
    
    fn from_pid(pid: u32) -> Result<Self, Box<dyn std::error::Error>> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
                false,
                pid
            )?
        };
        Ok(Self { handle, pid })
    }

    pub fn get_threads(&self) -> Result<Vec<RemoteThread>, Box<dyn std::error::Error>> {
        let snapshot = ThreadSnapshot::create()?;
        let found_threads = snapshot.filter(|te32| te32.th32OwnerProcessID == self.pid);

        // Use filter_map to keep only successful opens
        let remote_threads: Vec<RemoteThread> = found_threads
            .filter_map(|te32| {
                match RemoteThread::open(te32.th32ThreadID, THREAD_ALL_ACCESS) {
                    Ok(thread) => Some(thread), // Keep successful opens
                    Err(e) => {
                        // Log the error for debugging, but don't stop the collection
                        eprintln!("Warning: Failed to open thread {}: {}", te32.th32ThreadID, e);
                        None // Discard threads that failed to open
                    }
                }
            })
            .collect(); // Collects into Vec<RemoteThread>

        Ok(remote_threads)
    }

    pub fn get_windows(&self) -> Result<Vec<RemoteWindow>, Box<dyn std::error::Error>> {
        let mut enum_windows_data = EnumWindowsData {
            target_pid: self.pid,
            windows: Vec::new(),
        };

        unsafe {
            EnumWindows(Some(Self::enum_windows_callback), LPARAM(&mut enum_windows_data as *mut _ as isize))?;
        }

        Ok(enum_windows_data.windows)
    }

    // SAFETY: Caller must ensure that the lparam points to a valid EnumWindowsData
    unsafe extern "system" fn enum_windows_callback(
        hwnd: HWND,
        lparam: LPARAM
    ) -> BOOL {
        let data = unsafe { &mut *(lparam.0 as *mut EnumWindowsData) };

        let window = RemoteWindow::from(hwnd);

        if window.pid() != data.target_pid || !window.is_visible() {
            return BOOL(1);
        }

        data.windows.push(window);
        BOOL(1)
    }

    pub fn query_info<T>(&self, info_class: PROCESSINFOCLASS) -> Result<T, Box<dyn std::error::Error>> {
        let mut buffer: MaybeUninit<T> = MaybeUninit::uninit();
        let mut return_length: u32 = 0;

        let status = unsafe {
            NtQueryInformationProcess(
                self.handle(),
                info_class,
                &mut buffer as *mut _ as *mut c_void,
                std::mem::size_of::<T>() as u32,
                &mut return_length,
            )
        };

        if status.is_err() {
            return Err(format!("NtQueryInformationProcess failed: {:?}", status).into());
        }

        let initialized_buffer = unsafe { buffer.assume_init() };

        Ok(initialized_buffer)
    }

    pub unsafe fn read(&self, addr: *const c_void, size: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buffer = vec![0u8; size];
        unsafe {
            ReadProcessMemory(
                self.handle(),
                addr,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                None,
            )?;
        }
        Ok(buffer)
    }

    pub unsafe fn read_struct<T>(&self, addr: *const c_void) -> Result<T, Box<dyn std::error::Error>> {
        let mut buffer: MaybeUninit<T> = MaybeUninit::uninit();
        let size = std::mem::size_of::<T>();

        unsafe { ReadProcessMemory(
            self.handle(),
            addr,
            buffer.as_mut_ptr() as *mut c_void,
            size,
            None,
        ) }?;

        let initialized_buffer = unsafe { buffer.assume_init() };
        Ok(initialized_buffer)
    }

    pub fn write_wide_string(&self, s: &str) -> Result<AllocatedMemory, Box<dyn std::error::Error>> {
        let mut wide = to_wide(s);
        if *wide.last().unwrap_or(&0) != 0u16 {
            wide.push(0); // null-terminate if not already
        }

        let size = wide.len() * std::mem::size_of::<u16>();
        let allocated_memory = self.alloc(size, false)?;
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(wide.as_ptr() as *const u8, size)
        };

        allocated_memory.write(bytes)?;
        Ok(allocated_memory)
    }

    pub fn get_module(&self, module_name: &str) -> Result<RemoteModule, Box<dyn std::error::Error>> {
        let mut snapshot = ModuleSnapshot::create(self.pid)?;
        let found_entry = snapshot.find(|me32| {
            // find first null character
            let name_array = &me32.szModule;
            let len = name_array.iter().position(|&c| c == 0).unwrap_or(name_array.len());

            let os_name = OsString::from_wide(&name_array[..len]);
            
            // compare it case-insensitively
            os_name.eq_ignore_ascii_case(module_name)
        });

        match found_entry {
            Some(me32) => {
                let base = me32.modBaseAddr as usize;
                let hmodule = me32.hModule;

                let len = me32.szModule.iter().position(|&c| c == 0).unwrap_or(me32.szModule.len());
                let os_name = OsString::from_wide(&me32.szModule[..len]);
                
                Ok(RemoteModule::new(
                    &os_name.to_string_lossy(),
                    hmodule,
                    base
                ))
            }
            None => Err(format!("module '{}' not found in target", module_name).into()),
        }
    }

    /// # Safety
    /// The caller must ensure that `addr` is a valid pointer in the remote
    /// process with at least `data.len()` bytes of allocated memory.
    pub unsafe fn write(&self, addr: *mut c_void, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            WriteProcessMemory(
                self.handle(),
                addr,
                data.as_ptr() as *const c_void,
                data.len(),
                None
            )?;
        }
        Ok(())
    }

    /// # Safety
    /// The caller must ensure that `addr` is a valid pointer in the
    /// remote process that can safely be written to with `size_of::<T>()` bytes.
    /// The type `T` must be `#[repr(C)]`.
    pub unsafe fn write_struct<T: Sized>(
        &self,
        addr: *mut c_void,
        data: &T
    ) -> Result<(), Box<dyn std::error::Error>> {
        
        let bytes = unsafe { std::slice::from_raw_parts(
            data as *const T as *const u8,
            std::mem::size_of_val(data),
        ) };
        
        // Call your existing unsafe `write`
        unsafe { self.write(addr, bytes) }
    }


    // pub fn free_library(&self, lib_mod_handle: usize) -> Result<(), Box<dyn std::error::Error>> { // todo: fix/refactor this is for unloading DLLs
    //     let free_library_addr = self.get_remote_func_address("kernel32.dll", "FreeLibrary")?;
    //     let remote_thread = RemoteThread::from(
    //         unsafe { 
    //             CreateRemoteThread(
    //                 self.handle,
    //                 None,
    //                 0,
    //                 Some(std::mem::transmute(free_library_addr)),
    //                 Some(lib_mod_handle as *const c_void),
    //                 0,
    //                 None    
    //         )}
    //     ?);

    //     remote_thread.wait_until_active(std::time::Duration::from_millis(u32::MAX as u64))?;

    //     Ok(())
    // }
}

impl RemoteAllocator for RemoteProcess {
    fn alloc(&self, size: usize, exec: bool) -> Result<AllocatedMemory, Box<dyn std::error::Error>> {
        let prot = if exec { PAGE_EXECUTE_READWRITE } else { PAGE_READWRITE };
        let addr = unsafe {
            VirtualAllocEx(
                self.handle(),
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                prot,
            )
        };
        if addr.is_null() {
            return Err("Failed to allocate memory".into());
        }
        let allocated_memory = AllocatedMemory::new(addr, size, self.handle());
        Ok(allocated_memory)
    }
}

impl Drop for RemoteProcess {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.handle); }
    }
}