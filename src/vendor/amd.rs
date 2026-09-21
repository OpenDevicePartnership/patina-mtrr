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
    structs::{
        BASE_4GB, CPUID_SIGNATURE_AUTHENTIC_AMD_EBX, CPUID_SIGNATURE_AUTHENTIC_AMD_ECX,
        CPUID_SIGNATURE_AUTHENTIC_AMD_EDX, MSR_AMD64_SYSCFG, MSR_AMD64_TOP_MEM2, MsrAmd64SysCfg, MsrAmd64TopMem2,
        MtrrMemoryCacheType, MtrrMemoryRange,
    },
};

pub(super) fn is_vendor(vendor: &CpuidResult) -> bool {
    vendor.ebx == CPUID_SIGNATURE_AUTHENTIC_AMD_EBX
        && vendor.ecx == CPUID_SIGNATURE_AUTHENTIC_AMD_ECX
        && vendor.edx == CPUID_SIGNATURE_AUTHENTIC_AMD_EDX
}

/// Returns an MTRR override for the AMD Top Memory 2 region, if the appropriate system configuration flags are set.
pub(super) fn top_mem2_override(hal: &dyn Hal) -> Option<MtrrMemoryRange> {
    let syscfg = MsrAmd64SysCfg::from(hal.asm_read_msr64(MSR_AMD64_SYSCFG));
    if !syscfg.mtrr_tom2_en() || !syscfg.tom2_force_mem_type_wb() {
        return None;
    }

    let top_mem2 = MsrAmd64TopMem2::from(hal.asm_read_msr64(MSR_AMD64_TOP_MEM2)).address();
    if top_mem2 <= BASE_4GB {
        return None;
    }

    Some(MtrrMemoryRange::new(BASE_4GB, top_mem2 - BASE_4GB, MtrrMemoryCacheType::WriteBack))
}
