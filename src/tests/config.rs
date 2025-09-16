//! Test configuration and system parameter definitions.
//!
//! Provides centralized test configuration with predefined test system configurations
//! and const arrays that provide deterministic test data.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::structs::{
    MSR_IA32_MTRR_FIX4K_C0000, MSR_IA32_MTRR_FIX4K_C8000, MSR_IA32_MTRR_FIX4K_D0000, MSR_IA32_MTRR_FIX4K_D8000,
    MSR_IA32_MTRR_FIX4K_E0000, MSR_IA32_MTRR_FIX4K_E8000, MSR_IA32_MTRR_FIX4K_F0000, MSR_IA32_MTRR_FIX4K_F8000,
    MSR_IA32_MTRR_FIX16K_80000, MSR_IA32_MTRR_FIX16K_A0000, MSR_IA32_MTRR_FIX64K_00000, MtrrMemoryCacheType,
};

pub(crate) const BASIC_SYSTEM_PARAM_COUNT: usize = 3;
pub(crate) const CACHE_TYPE_COUNT: usize = 5;
pub(crate) const FIXED_MTRR_COUNT: usize = 11;
pub(crate) const SYSTEM_PARAM_TEST_COUNT: usize = 21;
pub(crate) const TEST_VALUE_COUNT: usize = 16;

/// System parameter configuration for MTRR testing.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MtrrLibSystemParameter {
    pub(crate) physical_address_bits: u8,
    pub(crate) mtrr_supported: bool,
    pub(crate) fixed_mtrr_supported: bool,
    pub(crate) default_cache_type: MtrrMemoryCacheType,
    pub(crate) variable_mtrr_count: u32,
    pub(crate) mk_tme_keyid_bits: u8,
}

impl MtrrLibSystemParameter {
    /// Creates a new system parameter configuration.
    pub(crate) const fn new(
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

impl Default for MtrrLibSystemParameter {
    fn default() -> Self {
        DEFAULT_SYSTEM_PARAMETER
    }
}

/// Builder for creating system parameter configurations.
#[derive(Debug, Clone)]
pub(crate) struct SystemParameterBuilder {
    config: MtrrLibSystemParameter,
}

impl SystemParameterBuilder {
    /// Creates a new builder with default parameters.
    pub(crate) fn new() -> Self {
        Self { config: DEFAULT_SYSTEM_PARAMETER }
    }

    /// Creates a new builder from an existing configuration.
    pub(crate) fn from(config: MtrrLibSystemParameter) -> Self {
        Self { config }
    }

    /// Sets the physical address bits.
    pub(crate) fn with_physical_address_bits(mut self, bits: u8) -> Self {
        self.config.physical_address_bits = bits;
        self
    }

    /// Sets MTRR support.
    pub(crate) fn with_mtrr_support(mut self, supported: bool) -> Self {
        self.config.mtrr_supported = supported;
        self
    }

    /// Sets fixed MTRR support.
    pub(crate) fn with_fixed_mtrr_support(mut self, supported: bool) -> Self {
        self.config.fixed_mtrr_supported = supported;
        self
    }

    /// Sets the default cache type.
    pub(crate) fn with_default_cache_type(mut self, cache_type: MtrrMemoryCacheType) -> Self {
        self.config.default_cache_type = cache_type;
        self
    }

    /// Sets the variable MTRR count.
    pub(crate) fn with_variable_mtrr_count(mut self, count: u32) -> Self {
        self.config.variable_mtrr_count = count;
        self
    }

    /// Sets the MK-TME (Multi-Key Total Memory Encryption) ID bits.
    pub(crate) fn with_mk_tme_keyid_bits(mut self, bits: u8) -> Self {
        self.config.mk_tme_keyid_bits = bits;
        self
    }

    /// Builds the final configuration.
    pub(crate) fn build(self) -> MtrrLibSystemParameter {
        self.config
    }

    /// Convenience method for creating a no-MTRR configuration.
    pub(crate) fn no_mtrr_support() -> Self {
        Self::new().with_mtrr_support(false).with_fixed_mtrr_support(false)
    }

    /// Convenience method for creating a no-fixed-MTRR configuration.
    pub(crate) fn no_fixed_mtrr_support() -> Self {
        Self::new().with_mtrr_support(true).with_fixed_mtrr_support(false)
    }
}

impl Default for SystemParameterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Default system parameter configuration for testing.
pub(crate) const DEFAULT_SYSTEM_PARAMETER: MtrrLibSystemParameter = MtrrLibSystemParameter {
    physical_address_bits: 42,
    mtrr_supported: true,
    fixed_mtrr_supported: true,
    default_cache_type: MtrrMemoryCacheType::Uncacheable,
    variable_mtrr_count: 12,
    mk_tme_keyid_bits: 0,
};

/// An array of system parameter configs.
pub(crate) const SYSTEM_PARAMETERS: [MtrrLibSystemParameter; BASIC_SYSTEM_PARAM_COUNT] = [
    MtrrLibSystemParameter {
        physical_address_bits: 36,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::Uncacheable,
        variable_mtrr_count: 8,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 40,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteBack,
        variable_mtrr_count: 10,
        mk_tme_keyid_bits: 0,
    },
    MtrrLibSystemParameter {
        physical_address_bits: 48,
        mtrr_supported: true,
        fixed_mtrr_supported: true,
        default_cache_type: MtrrMemoryCacheType::WriteBack,
        variable_mtrr_count: 16,
        mk_tme_keyid_bits: 0,
    },
];

/// A fixed set of predefined system parameter configurations.
pub(crate) const SYSTEM_PARAMETER_TEST_CONFIGS: [MtrrLibSystemParameter; SYSTEM_PARAM_TEST_COUNT] = [
    // Test configurations with 38-bit physical addressing
    MtrrLibSystemParameter::new(38, true, true, MtrrMemoryCacheType::Uncacheable, 12, 0),
    MtrrLibSystemParameter::new(38, true, true, MtrrMemoryCacheType::WriteBack, 12, 0),
    MtrrLibSystemParameter::new(38, true, true, MtrrMemoryCacheType::WriteThrough, 12, 0),
    MtrrLibSystemParameter::new(38, true, true, MtrrMemoryCacheType::WriteProtected, 12, 0),
    MtrrLibSystemParameter::new(38, true, true, MtrrMemoryCacheType::WriteCombining, 12, 0),
    // Test configurations with 42-bit physical addressing (default)
    MtrrLibSystemParameter::new(42, true, true, MtrrMemoryCacheType::Uncacheable, 12, 0),
    MtrrLibSystemParameter::new(42, true, true, MtrrMemoryCacheType::WriteBack, 12, 0),
    MtrrLibSystemParameter::new(42, true, true, MtrrMemoryCacheType::WriteThrough, 12, 0),
    MtrrLibSystemParameter::new(42, true, true, MtrrMemoryCacheType::WriteProtected, 12, 0),
    MtrrLibSystemParameter::new(42, true, true, MtrrMemoryCacheType::WriteCombining, 12, 0),
    // Test configurations with 48-bit physical addressing
    MtrrLibSystemParameter::new(48, true, true, MtrrMemoryCacheType::Uncacheable, 12, 0),
    MtrrLibSystemParameter::new(48, true, true, MtrrMemoryCacheType::WriteBack, 12, 0),
    MtrrLibSystemParameter::new(48, true, true, MtrrMemoryCacheType::WriteThrough, 12, 0),
    MtrrLibSystemParameter::new(48, true, true, MtrrMemoryCacheType::WriteProtected, 12, 0),
    MtrrLibSystemParameter::new(48, true, true, MtrrMemoryCacheType::WriteCombining, 12, 0),
    // Test configurations with fixed MTRRs disabled
    MtrrLibSystemParameter::new(48, true, false, MtrrMemoryCacheType::Uncacheable, 12, 0),
    MtrrLibSystemParameter::new(48, true, false, MtrrMemoryCacheType::WriteBack, 12, 0),
    MtrrLibSystemParameter::new(48, true, false, MtrrMemoryCacheType::WriteThrough, 12, 0),
    MtrrLibSystemParameter::new(48, true, false, MtrrMemoryCacheType::WriteProtected, 12, 0),
    MtrrLibSystemParameter::new(48, true, false, MtrrMemoryCacheType::WriteCombining, 12, 0),
    // Test configuration with MK-TME enabled (7 bits for MKTME)
    MtrrLibSystemParameter::new(48, true, true, MtrrMemoryCacheType::WriteBack, 12, 7),
];

/// Fixed MTRR register indices for testing.
pub(crate) const FIXED_MTRR_INDICES: [u32; FIXED_MTRR_COUNT] = [
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

/// Deterministic test values for 32-bit numbers.
pub(crate) const TEST_VALUES_32: [u32; TEST_VALUE_COUNT] = [
    0x12345678, 0x87654321, 0xABCDEF00, 0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF11, 0x22334455, 0x66778899,
    0xAABBCCDD, 0xEEFF1122, 0x33445566, 0x77889900, 0xBBCCDDEE, 0xFF112233, 0x44556677,
];

/// Deterministic test values for 64-bit numbers.
pub(crate) const TEST_VALUES_64: [u64; TEST_VALUE_COUNT] = [
    0x123456789ABCDEF0,
    0x0FEDCBA987654321,
    0xABCDEF0123456789,
    0x1122334455667788,
    0x99AABBCCDDEEFF00,
    0x5566778899AABBCC,
    0xDDEEFF0011223344,
    0x2233445566778899,
    0xAABBCCDDEEFF0011,
    0x6677889900112233,
    0xEEFF001122334455,
    0x3344556677889900,
    0xBBCCDDEEFF001122,
    0x7788990011223344,
    0xFF00112233445566,
    0x4455667788990011,
];

/// Cache type test patterns for deterministic testing.
pub(crate) const CACHE_TYPE_PATTERNS: [MtrrMemoryCacheType; CACHE_TYPE_COUNT] = [
    MtrrMemoryCacheType::Uncacheable,
    MtrrMemoryCacheType::WriteCombining,
    MtrrMemoryCacheType::WriteThrough,
    MtrrMemoryCacheType::WriteProtected,
    MtrrMemoryCacheType::WriteBack,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_parameter_builder() {
        let config = SystemParameterBuilder::new()
            .with_physical_address_bits(48)
            .with_mtrr_support(true)
            .with_fixed_mtrr_support(false)
            .with_default_cache_type(MtrrMemoryCacheType::WriteBack)
            .with_variable_mtrr_count(16)
            .with_mk_tme_keyid_bits(4)
            .build();

        assert_eq!(config.physical_address_bits, 48);
        assert!(config.mtrr_supported);
        assert!(!config.fixed_mtrr_supported);
        assert_eq!(config.default_cache_type, MtrrMemoryCacheType::WriteBack);
        assert_eq!(config.variable_mtrr_count, 16);
        assert_eq!(config.mk_tme_keyid_bits, 4);
    }

    #[test]
    fn test_default_system_parameter() {
        let default_config = MtrrLibSystemParameter::default();

        assert_eq!(default_config.physical_address_bits, 42);
        assert!(default_config.mtrr_supported);
        assert!(default_config.fixed_mtrr_supported);
        assert_eq!(default_config.default_cache_type, MtrrMemoryCacheType::Uncacheable);
        assert_eq!(default_config.variable_mtrr_count, 12);
        assert_eq!(default_config.mk_tme_keyid_bits, 0);
    }

    #[test]
    fn test_system_parameter_test_configs_validity() {
        for (index, config) in SYSTEM_PARAMETER_TEST_CONFIGS.iter().enumerate() {
            assert!(
                config.physical_address_bits >= 32 && config.physical_address_bits <= 64,
                "Config {} has invalid physical address bits: {}",
                index,
                config.physical_address_bits
            );
            assert!(
                config.variable_mtrr_count > 0,
                "Config {} has invalid variable MTRR count: {}",
                index,
                config.variable_mtrr_count
            );
            assert!(
                config.mk_tme_keyid_bits < config.physical_address_bits,
                "Config {} has MK-TME keyid bits >= physical address bits",
                index
            );
        }

        assert_eq!(
            SYSTEM_PARAMETER_TEST_CONFIGS.len(),
            SYSTEM_PARAM_TEST_COUNT,
            "Expected {} test configurations",
            SYSTEM_PARAM_TEST_COUNT
        );
    }
}
