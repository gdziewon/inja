use windows::Win32::Foundation::*;
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH};
use windows::Win32::System::Threading::{CreateThread, THREAD_CREATION_FLAGS};
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK};
use windows::core::BOOL;
use windows::core::*;
use core::ffi::c_void;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    _hinstance: HMODULE,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            let _ = CreateThread(
                None,
                0,
                Some(msg_box),
                None,
                THREAD_CREATION_FLAGS::default(),
                None,
            );
        }
    }

    TRUE
}

unsafe extern "system" fn msg_box(_param: *mut c_void) -> u32 {
    let text = h!("works!");
    let caption = h!("works!");
    unsafe {
        MessageBoxW(None, text, caption, MB_OK);
    }
    0
}
