use core::fmt;

use bitfield_struct::bitfield;

// Firmware needs to reserve 2 MTRRs for OS.
// Note: It is replaced by PCD PcdCpuNumberOfReservedVariableMtrrs.
const RESERVED_FIRMWARE_VARIABLE_MTRR_NUMBER: usize = 2;

pub const MSR_IA32_MTRRCAP: u32 = 0x000000FE; // Example MSR index for MSR_IA32_MTRRCAP
pub const MSR_IA32_MTRR_DEF_TYPE: u32 = 0x000002FF;
pub const MTRR_NUMBER_OF_VARIABLE_MTRR: usize = 32; // Adjust based on the actual number
pub const MTRR_NUMBER_OF_FIXED_MTRR: usize = 11;
pub const MTRR_NUMBER_OF_WORKING_MTRR_RANGES: usize = 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 2;
pub const MTRR_NUMBER_OF_LOCAL_MTRR_RANGES: usize =
    8 * MTRR_NUMBER_OF_FIXED_MTRR + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1;

pub const SIZE_1MB: u32 = 0x000100000;
pub const SIZE_64KB: u32 = 0x00010000;
pub const SIZE_16KB: u32 = 0x00004000;
pub const SIZE_4KB: u32 = 0x00001000;
pub const OR_SEED: u64 = 0x0101010101010101;
pub const CLEAR_SEED: u64 = 0xFFFFFFFFFFFFFFFF;
pub const MAX_WEIGHT: u8 = u8::MAX; // MAX_UINT8 in C maps to u8::MAX in Rust
pub const SCRATCH_BUFFER_SIZE: usize = 4 * SIZE_4KB as usize;

// Fixed MTRR msr
pub const MSR_IA32_MTRR_FIX64K_00000: u32 = 0x00000250;
pub const MSR_IA32_MTRR_FIX16K_80000: u32 = 0x00000258;
pub const MSR_IA32_MTRR_FIX16K_A0000: u32 = 0x00000259;
pub const MSR_IA32_MTRR_FIX4K_C0000: u32 = 0x00000268;
pub const MSR_IA32_MTRR_FIX4K_C8000: u32 = 0x00000269;
pub const MSR_IA32_MTRR_FIX4K_D0000: u32 = 0x0000026A;
pub const MSR_IA32_MTRR_FIX4K_D8000: u32 = 0x0000026B;
pub const MSR_IA32_MTRR_FIX4K_E0000: u32 = 0x0000026C;
pub const MSR_IA32_MTRR_FIX4K_E8000: u32 = 0x0000026D;
pub const MSR_IA32_MTRR_FIX4K_F0000: u32 = 0x0000026E;
pub const MSR_IA32_MTRR_FIX4K_F8000: u32 = 0x0000026F;

// Table for fixed MTRRs
pub const MMTRR_LIB_FIXED_MTRR_TABLE: [FixedMtrr; 11] = [
    FixedMtrr { msr: MSR_IA32_MTRR_FIX64K_00000, base_address: 0, length: SIZE_64KB },
    FixedMtrr { msr: MSR_IA32_MTRR_FIX16K_80000, base_address: 0x80000, length: SIZE_16KB },
    FixedMtrr { msr: MSR_IA32_MTRR_FIX16K_A0000, base_address: 0xA0000, length: SIZE_16KB },
    FixedMtrr { msr: MSR_IA32_MTRR_FIX4K_C0000, base_address: 0xC0000, length: SIZE_4KB },
    FixedMtrr { msr: MSR_IA32_MTRR_FIX4K_C8000, base_address: 0xC8000, length: SIZE_4KB },
    FixedMtrr { msr: MSR_IA32_MTRR_FIX4K_D0000, base_address: 0xD0000, length: SIZE_4KB },
    FixedMtrr { msr: MSR_IA32_MTRR_FIX4K_D8000, base_address: 0xD8000, length: SIZE_4KB },
    FixedMtrr { msr: MSR_IA32_MTRR_FIX4K_E0000, base_address: 0xE0000, length: SIZE_4KB },
    FixedMtrr { msr: MSR_IA32_MTRR_FIX4K_E8000, base_address: 0xE8000, length: SIZE_4KB },
    FixedMtrr { msr: MSR_IA32_MTRR_FIX4K_F0000, base_address: 0xF0000, length: SIZE_4KB },
    FixedMtrr { msr: MSR_IA32_MTRR_FIX4K_F8000, base_address: 0xF8000, length: SIZE_4KB },
];

// Variable MTRR msr
pub const MSR_IA32_MTRR_PHYSBASE0: u32 = 0x00000200;
// pub const MSR_IA32_MTRR_PHYSBASE1: u32 = 0x00000202;
// pub const MSR_IA32_MTRR_PHYSBASE2: u32 = 0x00000204;
// pub const MSR_IA32_MTRR_PHYSBASE3: u32 = 0x00000206;
// pub const MSR_IA32_MTRR_PHYSBASE4: u32 = 0x00000208;
// pub const MSR_IA32_MTRR_PHYSBASE5: u32 = 0x0000020A;
// pub const MSR_IA32_MTRR_PHYSBASE6: u32 = 0x0000020C;
// pub const MSR_IA32_MTRR_PHYSBASE7: u32 = 0x0000020E;
// pub const MSR_IA32_MTRR_PHYSBASE8: u32 = 0x00000210;
// pub const MSR_IA32_MTRR_PHYSBASE9: u32 = 0x00000212;

pub const MSR_IA32_MTRR_PHYSMASK0: u32 = 0x00000201;
// pub const MSR_IA32_MTRR_PHYSMASK1: u32 = 0x00000203;
// pub const MSR_IA32_MTRR_PHYSMASK2: u32 = 0x00000205;
// pub const MSR_IA32_MTRR_PHYSMASK3: u32 = 0x00000207;
// pub const MSR_IA32_MTRR_PHYSMASK4: u32 = 0x00000209;
// pub const MSR_IA32_MTRR_PHYSMASK5: u32 = 0x0000020B;
// pub const MSR_IA32_MTRR_PHYSMASK6: u32 = 0x0000020D;
// pub const MSR_IA32_MTRR_PHYSMASK7: u32 = 0x0000020F;
// pub const MSR_IA32_MTRR_PHYSMASK8: u32 = 0x00000211;
// pub const MSR_IA32_MTRR_PHYSMASK9: u32 = 0x00000213;

// Array of MTRR memory cache type short names
pub const MMTRR_MEMORY_CACHE_TYPE_SHORT_NAME: [&str; 8] = [
    "UC", // CacheUncacheable
    "WC", // CacheWriteCombining
    "R*", // Invalid
    "R*", // Invalid
    "WT", // CacheWriteThrough
    "WP", // CacheWriteProtected
    "WB", // CacheWriteBack
    "R*", // Invalid
];

// Structure to describe a fixed MTRR
#[repr(C)]
pub struct FixedMtrr {
    pub msr: u32,
    pub base_address: u32,
    pub length: u32,
}

// Structure to describe a variable MTRR
#[repr(C)]
#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VariableMtrr {
    pub base_address: u64,
    pub length: u64,
    pub mem_type: u8, // Type of the memory range.
    pub msr: u32,
    pub valid: bool, // Boolean for Valid.
    pub used: bool,  // Boolean for Used.
}

// Structure to hold base and mask pair for variable MTRR register
#[repr(C)]
#[derive(Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MtrrVariableSetting {
    pub base: u64,
    pub mask: u64,
}

// Array for variable MTRRs
#[repr(C)]
#[derive(Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MtrrVariableSettings {
    pub mtrr: [MtrrVariableSetting; MTRR_NUMBER_OF_VARIABLE_MTRR],
}

// Array for fixed MTRRs
#[repr(C)]
#[derive(Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MtrrFixedSettings {
    pub mtrr: [u64; MTRR_NUMBER_OF_FIXED_MTRR],
}

// Structure to hold all MTRRs
#[repr(C)]
#[derive(Default, PartialEq, Eq)]
pub struct MtrrSettings {
    pub fixed: MtrrFixedSettings,
    pub variables: MtrrVariableSettings,
    pub mtrr_def_type: u64,
}

impl MtrrSettings {
    pub fn new(fixed: MtrrFixedSettings, variables: MtrrVariableSettings, mtrr_def_type: u64) -> Self {
        Self { fixed, variables, mtrr_def_type }
    }
}

// Implement Display for MtrrVariableSetting
impl fmt::Display for MtrrVariableSetting {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Base: {:#018x}, Mask: {:#018x}", self.base, self.mask)
    }
}

// Implement Display for MtrrVariableSettings
impl fmt::Display for MtrrVariableSettings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result = String::new();
        for (i, mtrr) in self.mtrr.iter().enumerate() {
            result.push_str(&format!("Variable MTRR[{}]: {}\n", i, mtrr));
        }
        write!(f, "{}", result)
    }
}

// Implement Display for MtrrFixedSettings
impl fmt::Display for MtrrFixedSettings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result = String::new();
        for (i, mtrr) in self.mtrr.iter().enumerate() {
            result.push_str(&format!("Fixed MTRR[{}]: {:#018x}\n", i, mtrr));
        }
        write!(f, "{}", result)
    }
}

// Implement Display for MtrrSettings
impl fmt::Display for MtrrSettings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MTRR Settings:\nFixed MTRRs:\n{}\nVariable MTRRs:\n{}\nMTRR Default Type: {:#018x}",
            self.fixed, self.variables, self.mtrr_def_type
        )
    }
}

#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum MtrrMemoryCacheType {
    #[default]
    Uncacheable = 0,
    WriteCombining = 1,
    Reserved1 = 2,
    Reserved2 = 3,
    WriteThrough = 4,
    WriteProtected = 5,
    WriteBack = 6,
    Invalid = 7,
}

impl From<u8> for MtrrMemoryCacheType {
    fn from(value: u8) -> Self {
        match value {
            0 => MtrrMemoryCacheType::Uncacheable,
            1 => MtrrMemoryCacheType::WriteCombining,
            2 => MtrrMemoryCacheType::Reserved1,
            3 => MtrrMemoryCacheType::Reserved2,
            4 => MtrrMemoryCacheType::WriteThrough,
            5 => MtrrMemoryCacheType::WriteProtected,
            6 => MtrrMemoryCacheType::WriteBack,
            7 => MtrrMemoryCacheType::Invalid,
            _ => panic!("Invalid MTRR_MEMORY_CACHE_TYPE value: {}", value),
        }
    }
}

// Structure to describe an MTRR memory range
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct MtrrMemoryRange {
    pub base_address: u64,
    pub length: u64,
    pub mem_type: MtrrMemoryCacheType, // Use the MtrrMemoryCacheType enum.
}

impl MtrrMemoryRange {
    pub fn new(base_address: u64, length: u64, mem_type: MtrrMemoryCacheType) -> Self {
        Self { base_address, length, mem_type }
    }
}

// Structure to save and restore MTRR context
#[repr(C)]
#[derive(Default)]
pub struct MtrrContext {
    pub cr4: u64,                     // UINTN in C corresponds to usize in Rust
    pub interrupt_state: bool,        // BOOLEAN in C becomes bool in Rust
    pub def_type: MsrIa32MtrrDefType, // Assume MsrIa32MtrrDefType is defined elsewhere
}

// Structure for MTRR Lib Address
#[repr(C)]
#[derive(Default)]
pub struct MtrrLibAddress {
    pub address: u64,
    pub alignment: u64,
    pub length: u64,
    pub mem_type: u8, // Use u8 for the 7-bit MTRR_MEMORY_CACHE_TYPE

    // Temporary fields for MTRR calculation
    pub visited: bool, // 1-bit boolean
    pub weight: u8,    // UINT8
    pub previous: u16, // UINT16
}

pub const BIT11: u64 = 0x800;
pub const BIT7: u64 = 0x80;
pub const CPUID_EXTENDED_FUNCTION: u32 = 0x80000000;
pub const CPUID_SIGNATURE: u32 = 0;
pub const CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS: u32 = 0x07;
pub const CPUID_VERSION_INFO: u32 = 0x00000001;
pub const CPUID_VIR_PHY_ADDRESS_SIZE: u32 = 0x80000008;
pub const MSR_IA32_TME_ACTIVATE: u32 = 0x00000982;

/**
  MSR information returned for MSR index #MSR_IA32_MTRR_DEF_TYPE
**/
// translated from MSR_IA32_MTRR_DEF_TYPE_REGISTER in
// MU_BASECORE\MdePkg\Include\Register\Intel\ArchitecturalMsr.h

#[bitfield(u64)]
pub struct MsrIa32MtrrDefType {
    #[bits(3)]
    pub mem_type: u8, // [Bits 2:0] Default Memory Type (3 bits)
    #[bits(7)]
    pub reserved1: u8, // [Bits 9:3] Reserved (7 bits)
    #[bits(1)]
    pub fe: bool, // [Bit 10] Fixed Range MTRR Enable (1 bit)
    #[bits(1)]
    pub e: bool, // [Bit 11] MTRR Enable (1 bit)
    #[bits(52)]
    pub reserved: u64, // [Bits 31:12] Reserved (20 bits)
}

#[bitfield(u64)]
pub struct MsrIa32MtrrPhysbaseRegister {
    #[bits(8)]
    pub mem_type: u8, // [Bits 7:0] Type. Specifies memory type of the range.
    #[bits(4)]
    pub reserved1: u8, // [Bits 11:8] Reserved.
    #[bits(40)]
    pub phys_base: u64, // [Bits 51:12] PhysBase. MTRR physical Base Address.
    #[bits(12)]
    pub reserved2: u32, // [Bits MAXPHYSADDR:32] PhysBase. Upper bits of MTRR physical Base Address.
}

#[bitfield(u64)]
pub struct MsrIa32MtrrPhysmaskRegister {
    #[bits(11)]
    pub reserved1: u16, //
    #[bits(1)]
    pub v: bool, // [Bit 11] Valid Enable range mask.
    #[bits(40)]
    pub phys_mask: u64, // [Bits 51:12] PhysMask. MTRR physical Base Address.
    #[bits(12)]
    pub reserved2: u32, // [Bits MAXPHYSADDR:32] PhysBase. Upper bits of MTRR physical Base Address.
}

/**
  CPUID Version Information returned in EDX for CPUID leaf
  #CPUID_VERSION_INFO.
**/
// translated from CPUID_VERSION_INFO_EDX in
// MU_BASECORE\MdePkg\Include\Register\Intel\Cpuid.h

#[bitfield(u32)]
pub struct CpuidVersionInfoEdx {
    #[bits(1)]
    pub fpu: bool, // [Bit 0] Floating Point Unit On-Chip
    #[bits(1)]
    pub vme: bool, // [Bit 1] Virtual 8086 Mode Enhancements
    #[bits(1)]
    pub de: bool, // [Bit 2] Debugging Extensions
    #[bits(1)]
    pub pse: bool, // [Bit 3] Page Size Extension
    #[bits(1)]
    pub tsc: bool, // [Bit 4] Time Stamp Counter
    #[bits(1)]
    pub msr: bool, // [Bit 5] Model Specific Registers
    #[bits(1)]
    pub pae: bool, // [Bit 6] Physical Address Extension
    #[bits(1)]
    pub mce: bool, // [Bit 7] Machine Check Exception
    #[bits(1)]
    pub cx8: bool, // [Bit 8] CMPXCHG8B Instruction
    #[bits(1)]
    pub apic: bool, // [Bit 9] APIC On-Chip
    #[bits(1)]
    pub reserved1: bool, // [Bit 10] Reserved
    #[bits(1)]
    pub sep: bool, // [Bit 11] SYSENTER and SYSEXIT Instructions
    #[bits(1)]
    pub mtrr: bool, // [Bit 12] Memory Type Range Registers
    #[bits(1)]
    pub pge: bool, // [Bit 13] Page Global Bit
    #[bits(1)]
    pub mca: bool, // [Bit 14] Machine Check Architecture
    #[bits(1)]
    pub cmov: bool, // [Bit 15] Conditional Move Instructions
    #[bits(1)]
    pub pat: bool, // [Bit 16] Page Attribute Table
    #[bits(1)]
    pub pse_36: bool, // [Bit 17] 36-Bit Page Size Extension
    #[bits(1)]
    pub psn: bool, // [Bit 18] Processor Serial Number
    #[bits(1)]
    pub clfsh: bool, // [Bit 19] CLFLUSH Instruction
    #[bits(1)]
    pub reserved2: bool, // [Bit 20] Reserved
    #[bits(1)]
    pub ds: bool, // [Bit 21] Debug Store
    #[bits(1)]
    pub acpi: bool, // [Bit 22] Thermal Monitor & Clock Facilities
    #[bits(1)]
    pub mmx: bool, // [Bit 23] Intel MMX Technology
    #[bits(1)]
    pub fxsr: bool, // [Bit 24] FXSAVE and FXRSTOR Instructions
    #[bits(1)]
    pub sse: bool, // [Bit 25] SSE
    #[bits(1)]
    pub sse2: bool, // [Bit 26] SSE2
    #[bits(1)]
    pub ss: bool, // [Bit 27] Self Snoop
    #[bits(1)]
    pub htt: bool, // [Bit 28] Max APIC IDs reserved field is Valid
    #[bits(1)]
    pub tm: bool, // [Bit 29] Thermal Monitor
    #[bits(1)]
    pub reserved3: bool, // [Bit 30] Reserved
    #[bits(1)]
    pub pbe: bool, // [Bit 31] Pending Break Enable
}

/*
  MSR information returned for MSR index #MSR_IA32_MTRRCAP
*/
// translated from MSR_IA32_MTRRCAP_REGISTER in
// MU_BASECORE\MdePkg\Include\Register\Intel\ArchitecturalMsr.h

#[bitfield(u32)]
pub struct MsrIa32MtrrcapRegister {
    #[bits(8)]
    pub vcnt: u8, // [Bits 7:0] VCNT: Number of variable memory type ranges
    #[bits(1)]
    pub fix: bool, // [Bit 8] Fixed range MTRRs supported when set
    #[bits(1)]
    pub reserved1: bool, // [Bit 9] Reserved
    #[bits(1)]
    pub wc: bool, // [Bit 10] WC Supported when set
    #[bits(1)]
    pub smrr: bool, // [Bit 11] SMRR Supported when set
    #[bits(20)]
    pub reserved: u32,
}

#[bitfield(u32)]
pub struct CpuidVirPhyAddressSizeEax {
    /// Number of physical address bits.
    #[bits(8)]
    pub physical_address_bits: u8,

    /// Number of linear address bits.
    #[bits(8)]
    pub linear_address_bits: u8,

    /// Reserved field.
    #[bits(16)]
    pub reserved: u16,
}

#[bitfield(u32)]
pub struct CpuidStructuredExtendedFeatureFlagsEcx {
    /// [Bit 0] If 1 indicates the processor supports the PREFETCHWT1 instruction.
    #[bits(1)]
    pub prefetchwt1: bool,

    /// [Bit 1] AVX512_VBMI.
    #[bits(1)]
    pub avx512_vbmi: bool,

    /// [Bit 2] Supports user-mode instruction prevention if 1.
    #[bits(1)]
    pub umip: bool,

    /// [Bit 3] Supports protection keys for user-mode pages if 1.
    #[bits(1)]
    pub pku: bool,

    /// [Bit 4] If 1, OS has set CR4.PKE to enable protection keys (and the RDPKRU/WRPKRU instructions).
    #[bits(1)]
    pub ospke: bool,

    /// Reserved bits
    #[bits(8)]
    pub reserved8: u8,

    /// [Bit 13] If 1, the following MSRs are supported: IA32_TME_CAPABILITY, IA32_TME_ACTIVATE, IA32_TME_EXCLUDE_MASK, and IA32_TME_EXCLUDE_BASE.
    #[bits(1)]
    pub tme_en: bool,

    /// [Bits 14] AVX512_VPOPCNTDQ. (Intel Xeon Phi only.).
    #[bits(1)]
    pub avx512_vpopcntdq: bool,

    /// Reserved bits
    #[bits(1)]
    pub reserved7: bool,

    /// [Bit 16] Supports 5-level paging if 1.
    #[bits(1)]
    pub five_level_page: bool,

    /// [Bits 21:17] The value of MAWAU used by the BNDLDX and BNDSTX instructions in 64-bit mode.
    #[bits(5)]
    pub mawau: u8,

    /// [Bit 22] RDPID and IA32_TSC_AUX are available if 1.
    #[bits(1)]
    pub rdpid: bool,

    /// Reserved bits
    #[bits(7)]
    pub reserved3: u8,

    /// [Bit 30] Supports SGX Launch Configuration if 1.
    #[bits(1)]
    pub sgx_lc: bool,

    /// Reserved bits
    #[bits(1)]
    pub reserved4: bool,
}

#[bitfield(u64)]
pub struct MsrIa32TmeActivateRegister {
    /// [Bit 0] Lock R/O: Will be set upon successful WRMSR (or first SMI); written value ignored.
    #[bits(1)]
    pub lock: bool,

    /// [Bit 1] Hardware Encryption Enable: This bit also enables MKTME; MKTME cannot be enabled without enabling encryption hardware.
    #[bits(1)]
    pub tme_enable: bool,

    /// [Bit 2] Key Select:
    /// 0: Create a new TME key (expected cold/warm boot).
    /// 1: Restore the TME key from storage (Expected when resume from standby).
    #[bits(1)]
    pub key_select: bool,

    /// [Bit 3] Save TME Key for Standby: Save key into storage to be used when resume from standby.
    #[bits(1)]
    pub save_key_for_standby: bool,

    /// [Bit 7:4] TME Policy/Encryption Algorithm: Only algorithms enumerated in IA32_TME_CAPABILITY are allowed.
    /// For example:
    ///   0000 – AES-XTS-128.
    ///   0001 – AES-XTS-128 with integrity.
    ///   0010 – AES-XTS-256.
    ///   Other values are invalid.
    #[bits(4)]
    pub tme_policy: u8,

    /// Reserved bits
    #[bits(23)]
    pub reserved: u32,

    /// [Bit 31] TME Encryption Bypass Enable: When encryption hardware is enabled:
    /// * Total Memory Encryption is enabled using a CPU generated ephemeral key based on a hardware random number generator when this bit is set to 0.
    /// * Total Memory Encryption is bypassed (no encryption/decryption for KeyID0) when this bit is set to 1.
    #[bits(1)]
    pub tme_bypass_mode: u8,

    /// [Bit 35:32] MK_TME_KEYID_BITS: Reserved if MKTME is not enumerated, otherwise:
    /// The number of key identifier bits to allocate to MKTME usage.
    #[bits(4)]
    pub mk_tme_keyid_bits: u8,

    /// Reserved bits
    #[bits(12)]
    pub reserved2: u16,

    /// [Bit 63:48] MK_TME_CRYPTO_ALGS: Reserved if MKTME is not enumerated, otherwise:
    ///   Bit 48: AES-XTS 128.
    ///   Bit 49: AES-XTS 128 with integrity.
    ///   Bit 50: AES-XTS 256.
    ///   Bit 63:51: Reserved (#GP)
    /// Bitmask for BIOS to set which encryption algorithms are allowed for MKTME.
    #[bits(16)]
    pub mk_tme_crypto_algs: u16,
}
