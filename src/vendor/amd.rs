//! AMD-specific memory type overrides.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use crate::{
    hal::{CpuidResult, Hal},
    structs::{MtrrMemoryCacheType, MtrrMemoryRange},
};

const CPUID_SIGNATURE_AUTHENTIC_AMD_EBX: u32 = u32::from_le_bytes(*b"Auth");
const CPUID_SIGNATURE_AUTHENTIC_AMD_ECX: u32 = u32::from_le_bytes(*b"cAMD");
const CPUID_SIGNATURE_AUTHENTIC_AMD_EDX: u32 = u32::from_le_bytes(*b"enti");

const MSR_AMD64_SYSCFG: u32 = 0xC0010010;
const MSR_AMD64_TOP_MEM2: u32 = 0xC001001D;
const AMD64_SYSCFG_MTRR_TOM2_EN: u64 = 1 << 21;
const AMD64_SYSCFG_TOM2_FORCE_MEM_TYPE_WB: u64 = 1 << 22;
const AMD64_TOP_MEM2_ADDRESS_MASK: u64 = 0x000F_FFFF_FF80_0000;
const BASE_4GB: u64 = 0x1_0000_0000;

pub(super) fn is_vendor(vendor: &CpuidResult) -> bool {
    vendor.ebx == CPUID_SIGNATURE_AUTHENTIC_AMD_EBX
        && vendor.ecx == CPUID_SIGNATURE_AUTHENTIC_AMD_ECX
        && vendor.edx == CPUID_SIGNATURE_AUTHENTIC_AMD_EDX
}

/// Returns an MTRR override for the AMD Top Memory 2 region, if the appropriate system configuration flags are set.
pub(super) fn top_mem2_override(hal: &dyn Hal) -> Option<MtrrMemoryRange> {
    let syscfg = hal.asm_read_msr64(MSR_AMD64_SYSCFG);
    let required_flags = AMD64_SYSCFG_MTRR_TOM2_EN | AMD64_SYSCFG_TOM2_FORCE_MEM_TYPE_WB;
    if syscfg & required_flags != required_flags {
        return None;
    }

    let top_mem2 = hal.asm_read_msr64(MSR_AMD64_TOP_MEM2) & AMD64_TOP_MEM2_ADDRESS_MASK;
    if top_mem2 <= BASE_4GB {
        return None;
    }

    Some(MtrrMemoryRange::new(BASE_4GB, top_mem2 - BASE_4GB, MtrrMemoryCacheType::WriteBack))
}
