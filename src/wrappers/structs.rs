use std::ffi::c_void;
use bitflags::bitflags;

use windows::Win32::Foundation::{HANDLE, UNICODE_STRING};
use windows::Win32::System::Threading::{
    PEB_LDR_DATA, RTL_USER_PROCESS_PARAMETERS
};
use windows::Win32::System::Kernel::{LIST_ENTRY, SLIST_HEADER};

type BOOLEAN = u8;

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PebFlags: u8 {
        const IMAGE_USES_LARGE_PAGES = 1 << 0;
        const IS_PROTECTED_PROCESS = 1 << 1;
        const IS_IMAGE_DYNAMICALLY_RELOCATED = 1 << 2;
        const SKIP_PATCHING_USER32_FORWARDERS = 1 << 3;
        const IS_PACKAGED_PROCESS = 1 << 4;
        const IS_APP_CONTAINER = 1 << 5;
        const IS_PROTECTED_PROCESS_LIGHT = 1 << 6;
        const IS_LONG_PATH_AWARE_PROCESS = 1 << 7;
    }

    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CrossProcessFlags: u32 {
        const PROCESS_IN_JOB = 1 << 0;
        const PROCESS_INITIALIZING = 1 << 1;
        const PROCESS_USING_VEH = 1 << 2;
        const PROCESS_USING_VCH = 1 << 3;
        const PROCESS_USING_FTH = 1 << 4;
        const PROCESS_PREVIOUSLY_THROTTLED = 1 << 5;
        const PROCESS_CURRENTLY_THROTTLED = 1 << 6;
        const PROCESS_IMAGES_HOT_PATCHED = 1 << 7;
        // ReservedBits0 is implicit in the remaining bits
    }

    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TracingFlags: u32 {
        const HEAP_TRACING_ENABLED = 1 << 0;
        const CRIT_SEC_TRACING_ENABLED = 1 << 1;
        const LIB_LOADER_TRACING_ENABLED = 1 << 2;
        // SpareTracingBits is implicit
    }

    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LeapSecondFlags: u32 {
        const SIXTY_SECOND_ENABLED = 1 << 0;
        // Reserved is implicit
    }
}

#[repr(C)]
pub union PebBitfieldUnion {
    pub bit_field: BOOLEAN,
    pub flags: PebFlags,
}

#[repr(C)]
pub union CrossProcessFlagsUnion {
    pub cross_process_flags_value: u32,
    pub flags: CrossProcessFlags,
}

#[repr(C)]
pub union KernelCallbackTableUnion {
    pub kernel_callback_table: *mut c_void,
    pub user_shared_info_ptr: *mut c_void,
}

#[repr(C)]
pub union TracingFlagsUnion {
    pub tracing_flags_value: u32,
    pub flags: TracingFlags,
}

#[repr(C)]
pub union LeapSecondFlagsUnion {
    pub leap_second_flags_value: u32,
    pub flags: LeapSecondFlags,
}

#[repr(C)]
pub struct Peb {
    pub inherited_address_space: BOOLEAN,
    pub read_image_file_exec_options: BOOLEAN,
    pub being_debugged: BOOLEAN,
    pub bitfield_union: PebBitfieldUnion,
    pub padding0: [u8; 4],
    pub mutant: HANDLE,
    pub image_base_address: *mut c_void,
    pub ldr: *mut PEB_LDR_DATA,
    pub process_parameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub sub_system_data: *mut c_void,
    pub process_heap: *mut c_void,
    pub fast_peb_lock: *mut c_void, // *mut RTL_CRITICAL_SECTION
    pub atl_thunk_slist_ptr: *mut SLIST_HEADER,
    pub ifeo_key: *mut c_void,
    pub cross_process_flags_union: CrossProcessFlagsUnion,
    pub padding1: [u8; 4],
    pub kernel_callback_table_union: KernelCallbackTableUnion,
    pub system_reserved: u32,
    pub atl_thunk_slist_ptr32: u32,
    pub api_set_map: *mut c_void,
    pub tls_expansion_counter: u32,
    pub padding2: [u8; 4],
    pub tls_bitmap: *mut c_void,
    pub tls_bitmap_bits: [u32; 2],
    pub read_only_shared_memory_base: *mut c_void,
    pub shared_data: *mut c_void,
    pub read_only_static_server_data: *mut *mut c_void,
    pub ansi_code_page_data: *mut c_void,
    pub oem_code_page_data: *mut c_void,
    pub unicode_case_table_data: *mut c_void,
    pub number_of_processors: u32,
    pub nt_global_flag: u32,
    pub critical_section_timeout: u64, // LARGE_INTEGER
    pub heap_segment_reserve: u64,
    pub heap_segment_commit: u64,
    pub heap_decommit_total_free_threshold: u64,
    pub heap_decommit_free_block_threshold: u64,
    pub number_of_heaps: u32,
    pub maximum_number_of_heaps: u32,
    pub process_heaps: *mut *mut c_void,
    pub gdi_shared_handle_table: *mut c_void,
    pub process_starter_helper: *mut c_void,
    pub gdi_dc_attribute_list: u32,
    pub padding3: [u8; 4],
    pub loader_lock: *mut c_void, // *mut RTL_CRITICAL_SECTION
    pub os_major_version: u32,
    pub os_minor_version: u32,
    pub os_build_number: u16,
    pub os_csd_version: u16,
    pub os_platform_id: u32,
    pub image_subsystem: u32,
    pub image_subsystem_major_version: u32,
    pub image_subsystem_minor_version: u32,
    pub padding4: [u8; 4],
    pub active_process_affinity_mask: u64,
    pub gdi_handle_buffer: [u32; 60],
    pub post_process_init_routine: Option<unsafe extern "system" fn()>,
    pub tls_expansion_bitmap: *mut c_void,
    pub tls_expansion_bitmap_bits: [u32; 32],
    pub session_id: u32,
    pub padding5: [u8; 4],
    pub app_compat_flags: usize, // ULARGE_INTEGER
    pub app_compat_flags_user: usize, // ULARGE_INTEGER
    pub p_shim_data: *mut c_void,
    pub app_compat_info: *mut c_void,
    pub csd_version: UNICODE_STRING,
    pub activation_context_data: *mut c_void, // *mut ACTIVATION_CONTEXT_DATA
    pub process_assembly_storage_map: *mut c_void, // *mut ASSEMBLY_STORAGE_MAP
    pub system_default_activation_context_data: *mut c_void, // *mut ACTIVATION_CONTEXT_DATA
    pub system_assembly_storage_map: *mut c_void, // *mut ASSEMBLY_STORAGE_MAP
    pub minimum_stack_commit: u64,
    pub fls_callback: *mut c_void, // *mut FLS_CALLBACK_INFO
    pub fls_list_head: LIST_ENTRY,
    pub fls_bitmap: *mut c_void,
    pub fls_bitmap_bits: [u32; 4],
    pub fls_high_index: u32,
    pub wer_registration_data: *mut c_void,
    pub wer_ship_assert_ptr: *mut c_void,
    pub p_unused: *mut c_void,
    pub p_image_header_hash: *mut c_void,
    pub tracing_flags_union: TracingFlagsUnion,
    pub padding6: [u8; 4],
    pub csr_server_read_only_shared_memory_base: u64,
    pub tpp_workerp_list_lock: u64,
    pub tpp_workerp_list: LIST_ENTRY,
    pub wait_on_address_hash_table: [*mut c_void; 128],
    pub telemetry_coverage_header: *mut c_void,
    pub cloud_file_flags: u32,
    pub cloud_file_diag_flags: u32,
    pub placeholder_compatibility_mode: i8,
    pub placeholder_compatibility_mode_reserved: [i8; 7],
    pub leap_second_data: *mut c_void, // *mut LEAP_SECOND_DATA
    pub leap_second_flags_union: LeapSecondFlagsUnion,
    pub nt_global_flag2: u32,
}