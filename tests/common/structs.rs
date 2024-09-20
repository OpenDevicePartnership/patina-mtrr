use mtrr::{
    edk_error::{RETURN_BUFFER_TOO_SMALL, RETURN_SUCCESS},
    structs::{
        MsrIa32MtrrDefType, MsrIa32MtrrPhysbaseRegister, MsrIa32MtrrPhysmaskRegister, MtrrMemoryCacheType,
        MtrrMemoryRange, MtrrSettings, MtrrVariableSetting, MSR_IA32_MTRR_FIX16K_80000, MSR_IA32_MTRR_FIX16K_A0000,
        MSR_IA32_MTRR_FIX4K_C0000, MSR_IA32_MTRR_FIX4K_C8000, MSR_IA32_MTRR_FIX4K_D0000, MSR_IA32_MTRR_FIX4K_D8000,
        MSR_IA32_MTRR_FIX4K_E0000, MSR_IA32_MTRR_FIX4K_E8000, MSR_IA32_MTRR_FIX4K_F0000, MSR_IA32_MTRR_FIX4K_F8000,
        MSR_IA32_MTRR_FIX64K_00000, MTRR_NUMBER_OF_FIXED_MTRR, MTRR_NUMBER_OF_LOCAL_MTRR_RANGES,
        MTRR_NUMBER_OF_VARIABLE_MTRR, SIZE_1MB,
    },
};

pub const SCRATCH_BUFFER_SIZE: usize = 16 * 1024; // 16KB equivalent

#[repr(C)]
pub struct MtrrLibSystemParameter {
    pub physical_address_bits: u8,
    pub mtrr_supported: bool,
    pub fixed_mtrr_supported: bool,
    pub default_cache_type: MtrrMemoryCacheType, // Assuming this is an enum or type alias
    pub variable_mtrr_count: u32,
    pub mk_tme_keyid_bits: u8,
}

impl MtrrLibSystemParameter {
    pub fn new(
        physical_address_bits: u8,
        mtrr_supported: bool,
        fixed_mtrr_supported: bool,
        default_cache_type: MtrrMemoryCacheType,
        variable_mtrr_count: u32,
        mk_tme_keyid_bits: u8,
    ) -> Self {
        Self {
            physical_address_bits,
            mtrr_supported,
            fixed_mtrr_supported,
            default_cache_type,
            variable_mtrr_count,
            mk_tme_keyid_bits,
        }
    }
}

pub static M_DEFAULT_SYSTEM_PARAMETER: MtrrLibSystemParameter = MtrrLibSystemParameter {
    physical_address_bits: 42,
    mtrr_supported: true,
    fixed_mtrr_supported: true,
    default_cache_type: MtrrMemoryCacheType::Uncacheable,
    variable_mtrr_count: 12,
    mk_tme_keyid_bits: 0,
};

pub static M_SYSTEM_PARAMETERS: [MtrrLibSystemParameter; 21] = [
    MtrrLibSystemParameter {
        physical_address_bits: 38,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::Uncacheable,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 38,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteBack,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 38,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteThrough,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 38,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteProtected,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 38,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteCombining,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 42,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::Uncacheable,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 42,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteBack,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 42,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteThrough,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 42,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteProtected,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 42,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteCombining,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 48,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::Uncacheable,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 48,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteBack,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 48,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteThrough,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 48,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteProtected,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 48,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteCombining,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 48,
        mtrr_supported: true,
        fixed_mtrr_supported: false,
        default_cache_type: MtrrMemoryCacheType::Uncacheable,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 48,
        mtrr_supported: true,
        fixed_mtrr_supported: false,
        default_cache_type: MtrrMemoryCacheType::WriteBack,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 48,
        mtrr_supported: true,
        fixed_mtrr_supported: false,
        default_cache_type: MtrrMemoryCacheType::WriteThrough,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 48,
        mtrr_supported: true,
        fixed_mtrr_supported: false,
        default_cache_type: MtrrMemoryCacheType::WriteProtected,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 48,
        mtrr_supported: true,
        fixed_mtrr_supported: false,
        default_cache_type: MtrrMemoryCacheType::WriteCombining,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 48,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteBack,
        variable_mtrr_count: 12,
        mk_tme_keyid_bits: 7,
    }, // 7 bits for MKTME
];

pub const M_FIXED_MTRRS_INDEX: [u32; 11] = [
    MSR_IA32_MTRR_FIX64K_00000,
    MSR_IA32_MTRR_FIX16K_80000,
    MSR_IA32_MTRR_FIX16K_A0000,
    MSR_IA32_MTRR_FIX4K_C0000,
    MSR_IA32_MTRR_FIX4K_C8000,
    MSR_IA32_MTRR_FIX4K_D0000,
    MSR_IA32_MTRR_FIX4K_D8000,
    MSR_IA32_MTRR_FIX4K_E0000,
    MSR_IA32_MTRR_FIX4K_E8000,
    MSR_IA32_MTRR_FIX4K_F0000,
    MSR_IA32_MTRR_FIX4K_F8000,
];

#[derive(Copy, Clone)]
struct MtrrLibTestContext<'a> {
    system_parameter: &'a MtrrLibSystemParameter,
}

#[derive(Copy, Clone)]
struct MtrrLibGetFirmwareVariableMtrrCountContext<'a> {
    number_of_reserved_variable_mtrrs: u32,
    system_parameter: &'a MtrrLibSystemParameter,
}

// Static array for cache descriptions
static CACHE_DESCRIPTION: &'static [&str] = &["UC", "WC", "N/A", "N/A", "WT", "WP", "WB"];
