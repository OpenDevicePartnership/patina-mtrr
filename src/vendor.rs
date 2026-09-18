//! CPU vendor-specific memory type overrides.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
mod amd;
mod intel;

use crate::{
    hal::Hal,
    structs::{CPUID_SIGNATURE, MtrrMemoryCacheType, MtrrMemoryRange},
};

pub(crate) type MtrrOverrideFn = fn(&dyn Hal) -> Option<MtrrMemoryRange>;

/// Iterator over any CPU vendor-specific MTRR overrides.
pub(crate) struct MtrrOverrides<'a> {
    hal: &'a dyn Hal,
    overrides: core::slice::Iter<'static, MtrrOverrideFn>,
}

impl<'a> MtrrOverrides<'a> {
    /// Creates a new iterator over CPU vendor-specific MTRR overrides.
    pub(crate) fn new(hal: &'a dyn Hal, overrides: &'static [MtrrOverrideFn]) -> Self {
        Self { hal, overrides: overrides.iter() }
    }
}

impl Iterator for MtrrOverrides<'_> {
    type Item = MtrrMemoryRange;

    fn next(&mut self) -> Option<Self::Item> {
        self.overrides.find_map(|mtrr_override| mtrr_override(self.hal))
    }
}

/// CPU vendor enumeration.
///
/// Provides various utility functions that have different behavior depending on the CPU vendor.
#[derive(Clone, Copy)]
pub(crate) enum CpuVendor {
    Amd,
    Intel,
    Unknown,
}

impl CpuVendor {
    /// Detects the CPU vendor based on the CPUID signature.
    pub(crate) fn detect(hal: &dyn Hal) -> Self {
        let vendor = hal.asm_cpuid(CPUID_SIGNATURE);

        if amd::is_vendor(&vendor) {
            Self::Amd
        } else if intel::is_vendor(&vendor) {
            Self::Intel
        } else {
            Self::Unknown
        }
    }

    /// Returns an iterator over the CPU vendor-specific MTRR override ranges.
    pub(crate) fn mtrr_overrides(self, hal: &dyn Hal) -> MtrrOverrides<'_> {
        match self {
            Self::Amd => MtrrOverrides::new(hal, &[amd::top_mem2_override]),
            Self::Intel | Self::Unknown => MtrrOverrides::new(hal, &[]),
        }
    }

    /// Returns the vendor-specific MTRR override for an address, if one exists.
    pub(crate) fn mtrr_override(self, hal: &dyn Hal, address: u64) -> Option<MtrrMemoryCacheType> {
        self.mtrr_overrides(hal)
            .find(|range| address >= range.base_address && address < range.base_address.saturating_add(range.length))
            .map(|range| range.mem_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::X64Hal;

    fn disabled_override(_hal: &dyn Hal) -> Option<MtrrMemoryRange> {
        None
    }

    fn write_through_override(_hal: &dyn Hal) -> Option<MtrrMemoryRange> {
        Some(MtrrMemoryRange::new(0x1000, 0x1000, MtrrMemoryCacheType::WriteThrough))
    }

    fn write_protected_override(_hal: &dyn Hal) -> Option<MtrrMemoryRange> {
        Some(MtrrMemoryRange::new(0x3000, 0x1000, MtrrMemoryCacheType::WriteProtected))
    }

    #[test]
    fn mtrr_overrides_yields_all_enabled_ranges() {
        const OVERRIDES: &[MtrrOverrideFn] = &[disabled_override, write_through_override, write_protected_override];

        let hal = X64Hal::new();
        let ranges: std::vec::Vec<_> = MtrrOverrides::new(&hal, OVERRIDES).collect();

        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].base_address, 0x1000);
        assert_eq!(ranges[0].mem_type, MtrrMemoryCacheType::WriteThrough);
        assert_eq!(ranges[1].base_address, 0x3000);
        assert_eq!(ranges[1].mem_type, MtrrMemoryCacheType::WriteProtected);
    }
}
