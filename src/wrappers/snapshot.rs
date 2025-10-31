use windows::Win32::{Foundation::{CloseHandle, HANDLE}, System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32First, Process32Next, Thread32First, Thread32Next, MODULEENTRY32W, PROCESSENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32}};

pub struct ModuleSnapshot {
    handle: HANDLE,
    entry: MODULEENTRY32W,
    first: bool,
}

impl ModuleSnapshot {
    pub fn create(pid: u32) -> Result<Self, Box<dyn std::error::Error>> {
        let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)? };
        let entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        
        Ok(ModuleSnapshot {
            handle,
            entry,
            first: true,
        })
    }
}

impl Drop for ModuleSnapshot {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.handle); }
    }
}

impl Iterator for ModuleSnapshot {
    type Item = MODULEENTRY32W;

    fn next(&mut self) -> Option<Self::Item> {
        let success = if self.first {
            self.first = false;
            unsafe { Module32FirstW(self.handle, &mut self.entry) }.is_ok()
        } else {
            unsafe { Module32NextW(self.handle, &mut self.entry) }.is_ok()
        };

        if success {
            Some(self.entry)
        } else {
            None
        }
    }
}

pub struct ThreadSnapshot {
    handle: HANDLE,
    entry: THREADENTRY32,
    first: bool,
}

impl ThreadSnapshot {
    pub fn create() -> Result<Self, Box<dyn std::error::Error>> {
        let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)? };
        let entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        Ok(ThreadSnapshot {
            handle,
            entry,
            first: true,
        })
    }
}

impl Drop for ThreadSnapshot {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.handle); }
    }
}

 impl Iterator for ThreadSnapshot {

    type Item = THREADENTRY32;


    fn next(&mut self) -> Option<Self::Item> {
        let success = if self.first {
            self.first = false;
            unsafe { Thread32First(self.handle, &mut self.entry) }.is_ok()
        } else {
            unsafe { Thread32Next(self.handle, &mut self.entry) }.is_ok()
        };

        if success {
            Some(self.entry)
        } else {
            None
        }
    }
} 

pub struct ProcessSnapshot {
    handle: HANDLE,
    entry: PROCESSENTRY32,
    first: bool,
}

impl ProcessSnapshot {
    pub fn create() -> Result<Self, Box<dyn std::error::Error>> {
        let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };
        let entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        Ok(ProcessSnapshot {
            handle,
            entry,
            first: true,
        })
    }
}

impl Drop for ProcessSnapshot {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.handle); }
    }
}

impl Iterator for ProcessSnapshot {
    type Item = PROCESSENTRY32;

    fn next(&mut self) -> Option<Self::Item> {
        let success = if self.first {
            self.first = false;
            unsafe { Process32First(self.handle, &mut self.entry) }.is_ok()
        } else {
            unsafe { Process32Next(self.handle, &mut self.entry) }.is_ok()
        };

        if success {
            Some(self.entry)
        } else {
            None
        }
    }
}