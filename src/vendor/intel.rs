//! Intel-specific memory type overrides.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use crate::{
    hal::CpuidResult,
    structs::{
        CPUID_SIGNATURE_GENUINE_INTEL_EBX, CPUID_SIGNATURE_GENUINE_INTEL_ECX, CPUID_SIGNATURE_GENUINE_INTEL_EDX,
    },
};

pub(super) fn is_vendor(vendor: &CpuidResult) -> bool {
    vendor.ebx == CPUID_SIGNATURE_GENUINE_INTEL_EBX
        && vendor.ecx == CPUID_SIGNATURE_GENUINE_INTEL_ECX
        && vendor.edx == CPUID_SIGNATURE_GENUINE_INTEL_EDX
}
