use std::{ffi::c_void, mem::offset_of};

use windows::{Wdk::System::Threading::ProcessBasicInformation, Win32::{Foundation::EXCEPTION_GUARD_PAGE, System::{Diagnostics::Debug::EXCEPTION_CONTINUE_EXECUTION, Kernel::LIST_ENTRY, Memory::{PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_READWRITE}, Threading::{PROCESS_BASIC_INFORMATION}}}};

use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use crate::{
    executor::ExecutionMethod,
    symbols::SymbolHandler,
    wrappers::{RtlVectoredHandlerList, AllocatedMemory, CrossProcessFlags, Module, Peb, RtlVectoredExceptionEntry, RemoteAllocator as _, RemoteProcess}
};

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

        let was_using_veh = remote_process.is_using_veh()?;

        // Read the VEH list head structure
        let vectored_list: RtlVectoredHandlerList = unsafe {
            remote_process.read_struct(veh_list_addr as *const c_void)?
        };

        // Calculate the address of the List field within LdrpVectorHandlerList
        let list_head_addr = veh_list_addr + offset_of!(RtlVectoredHandlerList, list);

        let old_first_entry_ptr = vectored_list.list.Flink;
        
        let fake_veh_malloc = remote_process.alloc(
            std::mem::size_of::<RtlVectoredExceptionEntry>(),
            false
        )?;
        let fake_veh_addr: usize = fake_veh_malloc.as_ptr() as usize;

        let flag_offset = offset_of!(RtlVectoredExceptionEntry, flag);

        let stub = build_shcode(
            inject_func_addr as u64,
            dll_path_mem_alloc.as_ptr() as u64,
            fake_veh_addr as u64,
            list_head_addr as u64
        )?;
        let shellcode_ptr = remote_process.alloc(stub.len(), true)?;
        shellcode_ptr.write(&stub)?;

        let encoded_shellcode = remote_process.encode_pointer(shellcode_ptr.as_ptr() as usize)?;

        let fake_veh = RtlVectoredExceptionEntry {
            list: LIST_ENTRY {
                Flink: old_first_entry_ptr,
                Blink: list_head_addr as *mut _,
            },
            p_flag: (fake_veh_malloc.as_ptr() as usize + flag_offset) as *mut usize,
            ref_count: 1,
            padding: 0,
            vectored_handler: encoded_shellcode as *const c_void,
            flag: 1,
        };

        fake_veh_malloc.write_struct(&fake_veh)?;
        
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
            let list_head_blink_addr = (list_head_addr + offset_of!(LIST_ENTRY, Blink)) as *mut c_void;
            unsafe {
                remote_process.write_struct(
                    list_head_blink_addr,
                    &fake_veh_addr
                )
            }?;
        }

        if !was_using_veh {
            let pbi = remote_process.query_info::<PROCESS_BASIC_INFORMATION>(ProcessBasicInformation)?;
            let mut peb: Peb = unsafe { remote_process.read_struct(pbi.PebBaseAddress as *const c_void)? };

            unsafe {
                peb.cross_process_flags_union.flags.insert(CrossProcessFlags::PROCESS_USING_VEH);
            }

            let cross_flags_addr = (pbi.PebBaseAddress as usize + offset_of!(Peb, cross_process_flags_union)) as *mut c_void;
            unsafe {
                remote_process.write_struct(cross_flags_addr, &peb.cross_process_flags_union)?;
            }
        }

        // trigger execution by exception PAGE_GUARD
        let ntdll = remote_process.get_module("ntdll.dll")?;
        let nt_delay_execution_addr = ntdll.get_func_addr("NtDelayExecution")?;

        let _old_nt_delay_execution_prot = remote_process.set_protection(nt_delay_execution_addr as *mut c_void, 1, PAGE_EXECUTE_READ | PAGE_GUARD)?;

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