//! Intel-specific memory type overrides.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use crate::hal::CpuidResult;

const CPUID_SIGNATURE_GENUINE_INTEL_EBX: u32 = u32::from_le_bytes(*b"Genu");
const CPUID_SIGNATURE_GENUINE_INTEL_ECX: u32 = u32::from_le_bytes(*b"ntel");
const CPUID_SIGNATURE_GENUINE_INTEL_EDX: u32 = u32::from_le_bytes(*b"ineI");

pub(super) fn is_vendor(vendor: &CpuidResult) -> bool {
    vendor.ebx == CPUID_SIGNATURE_GENUINE_INTEL_EBX
        && vendor.ecx == CPUID_SIGNATURE_GENUINE_INTEL_ECX
        && vendor.edx == CPUID_SIGNATURE_GENUINE_INTEL_EDX
}
