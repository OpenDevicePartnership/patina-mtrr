//! Test support utilities and helpers for MTRR library unit tests.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
#![allow(clippy::needless_range_loop)]
use crate::{
    hal::Hal,
    structs::{
        MSR_IA32_MTRR_DEF_TYPE, MSR_IA32_MTRR_PHYSBASE0, MSR_IA32_MTRR_PHYSMASK0, MTRR_NUMBER_OF_FIXED_MTRR,
        MTRR_NUMBER_OF_VARIABLE_MTRR, MsrIa32MtrrDefType, MsrIa32MtrrPhysbaseRegister, MsrIa32MtrrPhysmaskRegister,
        MtrrFixedSettings, MtrrMemoryCacheType, MtrrMemoryRange, MtrrSettings, MtrrVariableSettings,
    },
    tests::{
        MtrrLibSystemParameter,
        config::SystemParameterBuilder,
        fixtures::{MemoryTypeCounts, MtrrTestFixture, create_comprehensive_mtrr_test_setup},
        mock_hal::create_mtrr_lib_with_mock_hal,
        support::{DeterministicGenerator, MtrrPairGenerator, TestResultCollector, get_effective_memory_ranges},
    },
};
use std::panic;

use crate::{Mtrr, tests::config::SYSTEM_PARAMETERS};

//
//  Compare the actual memory ranges against expected memory ranges and return PASS when they match.
//
//  @param expected_memory_ranges      Expected memory ranges.
//  @param expected_memory_range_count Count of expected memory ranges.
//  @param actual_ranges               Actual memory ranges.
//  @param actual_range_count          Count of actual memory ranges.
//
fn verify_memory_ranges(
    expected_memory_ranges: &[MtrrMemoryRange],
    expected_memory_ranges_count: usize,
    actual_ranges: &[MtrrMemoryRange],
    actual_ranges_count: usize,
) {
    // Note: The actual count to be less than expected count when the actual consolidation is more efficient.
    if actual_ranges_count > expected_memory_ranges_count {
        // Note: Panicking here since this in in the tests module
        panic!(
            "Actual ranges count ({}) should not exceed expected count ({})",
            actual_ranges_count, expected_memory_ranges_count
        );
    }

    if actual_ranges_count < expected_memory_ranges_count {
        println!(
            "More efficient consolidation: actual={} ranges vs expected={} ranges",
            actual_ranges_count, expected_memory_ranges_count
        );
        return;
    }

    for index in 0..expected_memory_ranges_count {
        assert_eq!(expected_memory_ranges[index].base_address, actual_ranges[index].base_address);
        assert_eq!(expected_memory_ranges[index].length, actual_ranges[index].length);
        assert_eq!(expected_memory_ranges[index].mem_type, actual_ranges[index].mem_type);
    }
}

//
//  Dump the memory ranges.
//
//  @param ranges      Memory ranges to dump.
//  @param range_count Count of memory ranges.
//
#[allow(clippy::legacy_numeric_constants)]
fn dump_memory_ranges(ranges: &[MtrrMemoryRange], range_count: usize) {
    for index in 0..range_count {
        println!(
            "\t{{0x{:016x}, 0x{:016x}, {:?} }},",
            ranges[index].base_address, ranges[index].length, ranges[index].mem_type
        );
    }
}

//  Returns an iterator that generates count of MTRRs for each cache type using predefined test patterns.
fn memory_type_test_patterns(total_count: u32) -> impl Iterator<Item = MemoryTypeCounts> {
    // Each pattern is a tuple: (max_mtrr_count, [cache_type_sequence; 12])
    //
    // - max_mtrr_count: The maximum number of MTRRs this pattern will generate (capped by total_count)
    // - cache_type_sequence: Array of cache type indices that define the distribution pattern
    //
    // Cache type index mapping:
    //   0 = UC (Uncacheable)
    //   1 = WT (WriteThrough)
    //   2 = WB (WriteBack)
    //   3 = WP (WriteProtected)
    //   4 = WC (WriteCombining)
    //
    // The sequence is cycled through for each MTRR slot up to max_mtrr_count.
    //
    // For example, pattern (6, [0, 1, 2, 3, 4, 0, ...]) with total_count=6 would create:
    //   MTRR 0: UC (index 0)
    //   MTRR 1: WT (index 1)
    //   MTRR 2: WB (index 2)
    //   MTRR 3: WP (index 3)
    //   MTRR 4: WC (index 4)
    //   MTRR 5: UC (index 0, cycling back)
    //   Cache Type Count Result: UC=2, WT=1, WB=1, WP=1, WC=1
    //
    // - Patterns with mixed types are intended to test MTRR consolidation algorithms
    // - Patterns with repeated types are intended to test range merging behavior
    // - Different max_mtrr_counts are intended to test various system configurations
    const TEST_PATTERNS: [(u32, [usize; 12]); 8] = [
        (5, [0, 4, 2, 0, 2, 1, 2, 3, 2, 0, 0, 0]), // Pattern designed to create 7 ranges
        (6, [0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0]), // UC=2, WT=1, WB=1, WP=1, WC=1
        (6, [0, 4, 2, 0, 4, 2, 0, 0, 0, 0, 0, 0]), // UC=2, WT=2, WB=2
        (6, [0, 1, 0, 1, 2, 2, 0, 0, 0, 0, 0, 0]), // UC=2, WT=2, WB=2
        (8, [0, 1, 2, 3, 4, 0, 1, 2, 0, 0, 0, 0]), // UC=3, WT=1, WB=1, WP=1, WC=1
        (8, [0, 1, 2, 3, 4, 1, 2, 3, 0, 0, 0, 0]), // UC=2, WT=2, WB=2, WP=2, WC=1
        (6, [4, 4, 4, 2, 2, 2, 0, 0, 0, 0, 0, 0]), // WB=3, WC=3
        (4, [1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0]), // WT=4
    ];

    TEST_PATTERNS.iter().map(move |(total_mtrr_count, type_sequence)| {
        let mut result = MemoryTypeCounts::default();
        let actual_total = std::cmp::min(*total_mtrr_count, total_count);

        for i in 0..actual_total as usize {
            let cache_type_index = type_sequence[i % type_sequence.len()];
            match cache_type_index {
                0 => result.uc += 1,
                1 => result.wt += 1,
                2 => result.wb += 1,
                3 => result.wp += 1,
                4 => result.wc += 1,
                _ => {}
            }
        }

        println!(
            "Total MTRR [{}]: UC={}, WT={}, WB={}, WP={}, WC={}",
            result.total(),
            result.uc,
            result.wt,
            result.wb,
            result.wp,
            result.wc
        );

        result
    })
}

// Unit tests

#[test]
fn unit_test_is_mtrr_supported_when_capability_disabled() {
    let fixture = MtrrTestFixture::no_mtrr_support();
    assert!(!fixture.mtrr_lib().is_supported(), "Should not be supported when MTRR capability is disabled");
}

#[test]
fn unit_test_is_mtrr_supported_when_no_variable_or_fixed_mtrrs() {
    let fixture = MtrrTestFixture::default().with_config(|config| {
        config.with_mtrr_support(true).with_variable_mtrr_count(0).with_fixed_mtrr_support(false)
    });
    assert!(!fixture.mtrr_lib().is_supported(), "Should not be supported without variable or fixed MTRRs");
}

#[test]
fn unit_test_is_mtrr_supported_with_fixed_mtrrs_only() {
    let fixture = MtrrTestFixture::default()
        .with_config(|config| config.with_mtrr_support(true).with_variable_mtrr_count(0).with_fixed_mtrr_support(true));
    assert!(fixture.mtrr_lib().is_supported(), "Should be supported with fixed MTRRs only");
}

#[test]
fn unit_test_is_mtrr_supported_with_variable_mtrrs_only() {
    let fixture = MtrrTestFixture::default().with_config(|config| {
        config.with_mtrr_support(true).with_variable_mtrr_count(7).with_fixed_mtrr_support(false)
    });
    assert!(fixture.mtrr_lib().is_supported(), "Should be supported with variable MTRRs only");
}

#[test]
fn unit_test_is_mtrr_supported_with_both_variable_and_fixed_mtrrs() {
    let fixture = MtrrTestFixture::default()
        .with_config(|config| config.with_mtrr_support(true).with_variable_mtrr_count(7).with_fixed_mtrr_support(true));
    assert!(fixture.mtrr_lib().is_supported(), "Should be supported with both variable and fixed MTRRs");
}

#[test]
fn unit_test_get_variable_mtrr_count() {
    for count in 1..=MTRR_NUMBER_OF_VARIABLE_MTRR {
        let fixture = MtrrTestFixture::default()
            .with_config(|config| config.with_mtrr_support(false).with_variable_mtrr_count(count as u32));
        let result = fixture.mtrr_lib().get_variable_mtrr_count();
        assert_eq!(result, 0, "Should return 0 when MTRR capability is disabled, regardless of configured count");
    }

    for count in 1..=MTRR_NUMBER_OF_VARIABLE_MTRR {
        let fixture = MtrrTestFixture::default()
            .with_config(|config| config.with_mtrr_support(true).with_variable_mtrr_count(count as u32));
        let result = fixture.mtrr_lib().get_variable_mtrr_count();
        assert_eq!(result, count as u32, "Should return configured count when MTRR capability is enabled");
    }
}

#[test]
#[should_panic]
fn unit_test_get_variable_mtrr_count_exceeds_maximum() {
    let fixture = MtrrTestFixture::default()
        .with_config(|config| config.with_variable_mtrr_count(MTRR_NUMBER_OF_VARIABLE_MTRR as u32 + 1));
    let _ = fixture.mtrr_lib().get_variable_mtrr_count();
}

#[test]
#[should_panic]
fn unit_test_get_variable_mtrr_count_invalid_count() {
    let fixture =
        MtrrTestFixture::default().with_config(|config| config.with_mtrr_support(true).with_variable_mtrr_count(0xFF));
    let _ = fixture.mtrr_lib().get_variable_mtrr_count();
}

#[test]
fn unit_test_get_firmware_variable_mtrr_count_valid_reserved_ranges() {
    let base_fixture = MtrrTestFixture::new();
    let variable_count = base_fixture.system_parameter().variable_mtrr_count;

    for reserved_mtrr in 0..=variable_count {
        let mtrrlib = MtrrTestFixture::new().with_reserved_variable_mtrrs(reserved_mtrr).create_mtrr_lib();

        let result = mtrrlib.get_firmware_usable_variable_mtrr_count();
        assert_eq!(
            result,
            variable_count - reserved_mtrr,
            "Expected {} usable MTRRs with {} reserved",
            variable_count - reserved_mtrr,
            reserved_mtrr
        );
    }
}

#[test]
fn unit_test_get_firmware_variable_mtrr_count_reserved_exceeds_available() {
    let base_fixture = MtrrTestFixture::new();
    let variable_count = base_fixture.system_parameter().variable_mtrr_count;

    for reserved_mtrr in variable_count + 1..255 {
        let mtrrlib = MtrrTestFixture::new().with_reserved_variable_mtrrs(reserved_mtrr).create_mtrr_lib();

        let result = mtrrlib.get_firmware_usable_variable_mtrr_count();
        assert_eq!(
            result, 0,
            "Expected 0 usable MTRRs when reserving {} (more than available {})",
            reserved_mtrr, variable_count
        );
    }
}

#[test]
fn unit_test_get_firmware_variable_mtrr_count_maximum_reserved() {
    let mtrrlib = MtrrTestFixture::new().with_reserved_variable_mtrrs(u32::MAX).create_mtrr_lib();
    assert_eq!(mtrrlib.get_firmware_usable_variable_mtrr_count(), 0, "Expected 0 usable MTRRs when reserving u32::MAX");
}

#[test]
fn unit_test_get_firmware_variable_mtrr_count_mtrr_not_supported() {
    let mtrrlib = MtrrTestFixture::no_mtrr_support().with_reserved_variable_mtrrs(2).create_mtrr_lib();
    assert_eq!(
        mtrrlib.get_firmware_usable_variable_mtrr_count(),
        0,
        "Expected 0 usable MTRRs when MTRR support is disabled"
    );
}

#[test]
fn unit_test_get_firmware_variable_mtrr_count_fixed_mtrr_not_supported() {
    let base_fixture = MtrrTestFixture::new();
    let variable_count = base_fixture.system_parameter().variable_mtrr_count;

    let mtrrlib = MtrrTestFixture::no_fixed_mtrr_support().with_reserved_variable_mtrrs(2).create_mtrr_lib();
    let expected = variable_count - 2;
    assert_eq!(
        mtrrlib.get_firmware_usable_variable_mtrr_count(),
        expected,
        "Expected {} usable MTRRs with fixed MTRR support disabled and 2 reserved",
        expected
    );
}

#[test]
#[should_panic]
fn unit_test_get_firmware_variable_mtrr_count_exceeds_limit() {
    let mtrrlib = MtrrTestFixture::new()
        .with_system_parameter(
            SystemParameterBuilder::new().with_variable_mtrr_count(MTRR_NUMBER_OF_VARIABLE_MTRR as u32 + 1).build(),
        )
        .with_reserved_variable_mtrrs(2)
        .create_mtrr_lib();
    let _ = mtrrlib.get_firmware_usable_variable_mtrr_count();
}

#[test]
fn unit_test_mtrr_get_fixed_mtrr() {
    for _test_pattern in 0..8 {
        let fixture = MtrrTestFixture::with_deterministic_fixed_mtrrs();
        let expected_settings = fixture.get_expected_fixed_mtrr_settings();
        let result = fixture.mtrr_lib().mtrr_get_fixed_mtrr();

        assert_eq!(result.mtrr, expected_settings.mtrr, "Fixed MTRR settings should match deterministic pattern");
    }

    // Test: When MTRR support is disabled, should return default settings
    let fixture = MtrrTestFixture::default().with_config(|config| config.with_mtrr_support(false));
    let result = fixture.mtrr_lib().mtrr_get_fixed_mtrr();
    let expected = MtrrFixedSettings::default();

    assert_eq!(result.mtrr, expected.mtrr, "Should return default fixed MTRR settings when MTRR support is disabled");

    // Test: When fixed MTRR support is disabled, should return default settings
    let fixture =
        MtrrTestFixture::default().with_config(|config| config.with_mtrr_support(true).with_fixed_mtrr_support(false));
    let result = fixture.mtrr_lib().mtrr_get_fixed_mtrr();
    let expected = MtrrFixedSettings::default();

    assert_eq!(
        result.mtrr, expected.mtrr,
        "Should return default fixed MTRR settings when fixed MTRR support is disabled"
    );
}

#[test]
fn unit_test_mtrr_get_all_mtrrs_with_fixed_mtrrs_disabled() {
    let comprehensive_fixture = MtrrTestFixture::with_comprehensive_mtrr_setup()
        .with_config(|config| config.with_mtrr_support(true).with_fixed_mtrr_support(false));
    let expected = comprehensive_fixture.get_expected_comprehensive_mtrr_settings();
    let result = comprehensive_fixture.mtrr_lib().get_all_mtrrs().unwrap();

    assert!(result.fixed == expected.fixed, "Fixed MTRRs should match expected when fixed MTRRs are disabled");
    assert!(
        result.variables == expected.variables,
        "Variable MTRRs should match expected when fixed MTRRs are disabled"
    );
}

#[test]
fn unit_test_mtrr_get_all_mtrrs_with_fixed_mtrrs_enabled() {
    let comprehensive_fixture = MtrrTestFixture::with_comprehensive_mtrr_setup()
        .with_config(|config| config.with_mtrr_support(true).with_fixed_mtrr_support(true));
    let expected = comprehensive_fixture.get_expected_comprehensive_mtrr_settings();
    let result = comprehensive_fixture.mtrr_lib().get_all_mtrrs().unwrap();

    assert!(result.fixed == expected.fixed, "Fixed MTRRs should match expected when fixed MTRRs are enabled");
    assert!(
        result.variables == expected.variables,
        "Variable MTRRs should match expected when fixed MTRRs are enabled"
    );
}

#[test]
fn unit_test_mtrr_get_all_mtrrs_when_mtrr_support_disabled() {
    let fixture = MtrrTestFixture::default().with_config(|config| config.with_mtrr_support(false));
    let result = fixture.mtrr_lib().get_all_mtrrs();

    assert!(result.is_err(), "Should return error when MTRR support is disabled");
}

#[test]
#[should_panic]
fn unit_test_mtrr_get_all_mtrrs_when_variable_count_exceeds_maximum() {
    let fixture = MtrrTestFixture::default().with_config(|config| {
        config.with_mtrr_support(true).with_variable_mtrr_count(MTRR_NUMBER_OF_VARIABLE_MTRR as u32 + 1)
    });
    let _ = fixture.mtrr_lib().get_all_mtrrs().unwrap();
}

#[test]
fn unit_test_mtrr_set_all_mtrrs() {
    // Test: Set all MTRRs with comprehensive deterministic settings
    let fixture = MtrrTestFixture::default().with_config(|config| {
        config
            .with_physical_address_bits(42)
            .with_mtrr_support(true)
            .with_fixed_mtrr_support(true)
            .with_default_cache_type(MtrrMemoryCacheType::Uncacheable)
            .with_variable_mtrr_count(12)
    });

    let (hal, expected_settings) = create_comprehensive_mtrr_test_setup();
    let mut hal = hal;
    hal.initialize_mtrr_regs(&fixture.create_system_parameter());

    let mut mtrrlib = create_mtrr_lib_with_mock_hal(hal, 0);
    mtrrlib.set_all_mtrrs(&expected_settings);

    // Verify MSR values were written correctly
    let hal = mtrrlib.mtrr_drop_hal();

    assert_eq!(
        hal.asm_read_msr64(MSR_IA32_MTRR_DEF_TYPE),
        expected_settings.mtrr_def_type_reg.into_bits(),
        "Default type register should match expected value"
    );

    // Verify variable MTRR MSR values
    for index in 0..12u32 {
        assert_eq!(
            hal.asm_read_msr64(MSR_IA32_MTRR_PHYSBASE0 + (index * 2)),
            expected_settings.variables.mtrr[index as usize].base,
            "Variable MTRR base {} should match expected value",
            index
        );
        assert_eq!(
            hal.asm_read_msr64(MSR_IA32_MTRR_PHYSMASK0 + (index * 2)),
            expected_settings.variables.mtrr[index as usize].mask,
            "Variable MTRR mask {} should match expected value",
            index
        );
    }
}

#[test]
fn unit_test_mtrr_get_memory_attribute_in_variable_mtrr() {
    // Test main functionality with pre-configured variable MTRRs
    let (hal, expected_mtrr_settings) = crate::tests::fixtures::create_variable_mtrr_test_setup();
    let system_parameter = crate::tests::config::DEFAULT_SYSTEM_PARAMETER;
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal, 0);

    let valid_mtrr_bits_mask = (1u64 << system_parameter.physical_address_bits) - 1;
    let valid_mtrr_address_mask = valid_mtrr_bits_mask & 0xfffffffffffff000;

    let variable_mtrr =
        mtrrlib.mtrr_get_memory_attribute_in_variable_mtrr(valid_mtrr_bits_mask, valid_mtrr_address_mask);

    // Validate results match expected MTRR settings
    for index in 0..system_parameter.variable_mtrr_count as usize {
        let base = MsrIa32MtrrPhysbaseRegister::default()
            .with_phys_base((variable_mtrr[index].base_address & valid_mtrr_address_mask) >> 12)
            .with_mem_type(variable_mtrr[index].mem_type)
            .into_bits();

        assert_eq!(base, expected_mtrr_settings.variables.mtrr[index].base, "Variable MTRR {} base mismatch", index);

        let mask = MsrIa32MtrrPhysmaskRegister::default()
            .with_phys_mask(((!(variable_mtrr[index].length - 1)) & valid_mtrr_bits_mask) >> 12)
            .with_v(true)
            .into_bits();

        assert_eq!(mask, expected_mtrr_settings.variables.mtrr[index].mask, "Variable MTRR {} mask mismatch", index);
    }

    // Test when MTRRs are not supported
    let fixture = MtrrTestFixture::no_mtrr_support();
    let mtrrlib = fixture.mtrr_lib();
    let variable_mtrr =
        mtrrlib.mtrr_get_memory_attribute_in_variable_mtrr(valid_mtrr_bits_mask, valid_mtrr_address_mask);

    assert!(
        variable_mtrr.len() <= MTRR_NUMBER_OF_VARIABLE_MTRR,
        "Should not exceed max variable MTRRs when MTRRs not supported"
    );
    assert!(
        variable_mtrr.len() <= mtrrlib.get_firmware_usable_variable_mtrr_count() as usize,
        "Should not exceed firmware usable count when MTRRs not supported"
    );
}

#[test]
#[should_panic]
fn unit_test_get_memory_attribute_mtrr_count_exceeds_maximum() {
    let valid_mtrr_bits_mask = (1u64 << crate::tests::config::DEFAULT_SYSTEM_PARAMETER.physical_address_bits) - 1;
    let valid_mtrr_address_mask = valid_mtrr_bits_mask & 0xfffffffffffff000;

    let fixture = MtrrTestFixture::default()
        .with_config(|config| config.with_variable_mtrr_count(MTRR_NUMBER_OF_VARIABLE_MTRR as u32 + 1));
    let mtrrlib = fixture.mtrr_lib();
    let _variable_mtrr =
        mtrrlib.mtrr_get_memory_attribute_in_variable_mtrr(valid_mtrr_bits_mask, valid_mtrr_address_mask);
}

#[test]
fn unit_test_mtrr_get_default_memory_type() {
    // Test all supported cache types return correctly
    let cache_types = [
        MtrrMemoryCacheType::Uncacheable,
        MtrrMemoryCacheType::WriteCombining,
        MtrrMemoryCacheType::WriteThrough,
        MtrrMemoryCacheType::WriteProtected,
        MtrrMemoryCacheType::WriteBack,
    ];

    for &cache_type in &cache_types {
        let fixture = MtrrTestFixture::default().with_config(|config| config.with_default_cache_type(cache_type));
        let result = fixture.mtrr_lib().mtrr_get_default_memory_type();
        assert_eq!(result, cache_type, "Default cache type should match configured type");
    }

    // When MTRRs are not supported, always return Uncacheable
    let fixture = MtrrTestFixture::no_mtrr_support();
    let result = fixture.mtrr_lib().mtrr_get_default_memory_type();
    assert_eq!(result, MtrrMemoryCacheType::Uncacheable, "Should return Uncacheable when MTRRs not supported");

    // When Fixed MTRRs are not supported, return configured default
    let fixture = MtrrTestFixture::no_fixed_mtrr_support();
    let expected_type = fixture.system_parameter().default_cache_type;
    let result = fixture.mtrr_lib().mtrr_get_default_memory_type();
    assert_eq!(result, expected_type, "Should return configured default when Fixed MTRRs not supported");

    // When Variable MTRRs are not supported (count = 0), return configured default
    let fixture = MtrrTestFixture::default().with_config(|config| config.with_variable_mtrr_count(0));
    let expected_type = fixture.system_parameter().default_cache_type;
    let result = fixture.mtrr_lib().mtrr_get_default_memory_type();
    assert_eq!(result, expected_type, "Should return configured default when Variable MTRRs not supported");
}

#[test]
fn unit_test_invalid_memory_layouts() {
    let iterations = 1;
    for system_parameter in &SYSTEM_PARAMETERS {
        for i in 0..iterations {
            println!("Iteration: {i}");
            unit_test_invalid_memory_layouts_impl(system_parameter);
        }
    }
}

fn unit_test_invalid_memory_layouts_impl(system_parameter: &MtrrLibSystemParameter) {
    let mut ranges = [MtrrMemoryRange::default(); MTRR_NUMBER_OF_VARIABLE_MTRR * 2 + 1];

    let mut mtrrlib =
        MtrrTestFixture::new().with_config(|_config| SystemParameterBuilder::from(system_parameter.clone())).mtrr_lib();

    let mut generator = DeterministicGenerator::new(0);
    let range_count = generator.next_u32(1, ranges.len() as u32);
    let max_address = 1u64 << (system_parameter.physical_address_bits - system_parameter.mk_tme_keyid_bits);

    for index in 0..range_count {
        // Use values that are misaligned to ensure test failure conditions
        let base_address = generator.next_u64(0, max_address) | 0x1;
        let length = generator.next_u64(1, max_address - base_address) | 0x1;

        ranges[index as usize].base_address = base_address;
        ranges[index as usize].length = length;
        ranges[index as usize].mem_type = generator.next_cache_type();

        let status = mtrrlib.set_memory_attribute(
            ranges[index as usize].base_address,
            ranges[index as usize].length,
            ranges[index as usize].mem_type,
        );
        assert!(status.is_err());
    }

    for range in &ranges {
        let status = mtrrlib.set_memory_attribute(range.base_address, range.length, range.mem_type);
        assert!(status.is_err());
    }
}

#[test]
fn unit_test_mtrr_set_memory_attribute_and_get_memory_attributes() {
    for system_parameter in SYSTEM_PARAMETERS.iter() {
        unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_mtrr_settings(system_parameter);
        unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_empty_mtrr_settings(system_parameter);
    }
}

fn unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_mtrr_settings(
    system_parameter: &MtrrLibSystemParameter,
) {
    let mut status;

    let mut raw_mtrr_range = [MtrrMemoryRange::default(); MTRR_NUMBER_OF_VARIABLE_MTRR];
    let mut expected_memory_ranges = [MtrrMemoryRange::default();
        MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let mut expected_memory_ranges_count;

    let mut actual_memory_ranges = [MtrrMemoryRange::default();
        MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let mut actual_variable_mtrr_usage: u32;
    let mut actual_memory_ranges_count: usize;

    println!(
        "------------unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_mtrr_settings begin------------"
    );
    println!("system_parameter: {system_parameter:?}");

    for (pattern_index, memory_type_counts) in
        memory_type_test_patterns(system_parameter.variable_mtrr_count).enumerate()
    {
        println!("--- Testing with pattern {} ---", pattern_index);

        let mut mtrrlib = MtrrTestFixture::new()
            .with_config(|_config| SystemParameterBuilder::from(system_parameter.clone()))
            .mtrr_lib();

        let mut pair_generator = MtrrPairGenerator::new(0);
        let generated_ranges = pair_generator.generate_multiple_pairs(
            system_parameter.physical_address_bits as u32 - system_parameter.mk_tme_keyid_bits as u32,
            memory_type_counts,
        );

        for (i, range) in generated_ranges.iter().enumerate() {
            if i < raw_mtrr_range.len() {
                raw_mtrr_range[i] = *range;
            }
        }

        let raw_mtrr_range_count = memory_type_counts.total();
        expected_memory_ranges_count = expected_memory_ranges.len();

        println!("--- Raw MTRR Range [{raw_mtrr_range_count}]---");
        dump_memory_ranges(&raw_mtrr_range, raw_mtrr_range_count as usize);

        get_effective_memory_ranges(
            system_parameter.default_cache_type,
            system_parameter.physical_address_bits as u32 - system_parameter.mk_tme_keyid_bits as u32,
            &raw_mtrr_range[..],
            raw_mtrr_range_count as usize,
            &mut expected_memory_ranges[..],
            &mut expected_memory_ranges_count,
        );

        println!("--- Expected Memory Ranges [{expected_memory_ranges_count}] ---");
        dump_memory_ranges(&expected_memory_ranges, expected_memory_ranges_count);

        let default_mem_type = system_parameter.default_cache_type as u8;
        let default_mem_type_reg = MsrIa32MtrrDefType::default()
            .with_mem_type(default_mem_type)
            .with_e(true) // Enable MTRRs
            .with_fe(system_parameter.fixed_mtrr_supported); // Enable fixed MTRRs if supported

        let mtrr_setting =
            MtrrSettings::new(MtrrFixedSettings::default(), MtrrVariableSettings::default(), default_mem_type_reg);
        mtrrlib.set_all_mtrrs(&mtrr_setting);
        for index in 0..raw_mtrr_range_count as usize {
            println!("--------------------------------------------------");
            println!("--------------------------------------------------");
            println!("{index} calling set_memory_attribute");

            status = mtrrlib.set_memory_attribute(
                raw_mtrr_range[index].base_address,
                raw_mtrr_range[index].length,
                raw_mtrr_range[index].mem_type,
            );

            if status.is_err() {
                return;
            }
        }

        let mtrr_setting = mtrrlib.get_all_mtrrs().unwrap();
        let collector = TestResultCollector::new(
            system_parameter.default_cache_type,
            system_parameter.physical_address_bits as u32 - system_parameter.mk_tme_keyid_bits as u32,
            system_parameter.variable_mtrr_count,
        );
        let (result_ranges_count, result_variable_usage) =
            collector.collect_results(&mtrr_setting, &mut actual_memory_ranges);
        actual_memory_ranges_count = result_ranges_count;
        actual_variable_mtrr_usage = result_variable_usage;

        println!("--- System Parameter --- \n{system_parameter:?}");
        println!("--- Raw MTRR Range [{raw_mtrr_range_count}] ---");
        dump_memory_ranges(&raw_mtrr_range, raw_mtrr_range_count as usize);
        println!("--- Actual Memory Ranges [{actual_memory_ranges_count}] ---");
        dump_memory_ranges(&actual_memory_ranges, actual_memory_ranges_count);
        println!("--- Expected Memory Ranges [{expected_memory_ranges_count}] ---");
        dump_memory_ranges(&expected_memory_ranges, expected_memory_ranges_count);
        verify_memory_ranges(
            &expected_memory_ranges[..],
            expected_memory_ranges_count,
            &actual_memory_ranges,
            actual_memory_ranges_count,
        );
        assert!(raw_mtrr_range_count >= actual_variable_mtrr_usage);

        let returned_memory_ranges = mtrrlib.get_memory_ranges();
        assert!(returned_memory_ranges.is_ok());
        let returned_memory_ranges = returned_memory_ranges.unwrap();
        println!("--- Returned Memory Ranges [{}] ---", returned_memory_ranges.len());
        dump_memory_ranges(&returned_memory_ranges, returned_memory_ranges.len());
        verify_memory_ranges(
            &expected_memory_ranges,
            expected_memory_ranges_count,
            &returned_memory_ranges,
            returned_memory_ranges.len(),
        );
    }

    println!(
        "------------unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_mtrr_settings end------------"
    );
}

fn unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_empty_mtrr_settings(
    system_parameter: &MtrrLibSystemParameter,
) {
    let mut status;

    // let mut local_mtrrs = MtrrSettings::default();
    let mut raw_mtrr_range = [MtrrMemoryRange::default(); MTRR_NUMBER_OF_VARIABLE_MTRR];
    let mut expected_memory_ranges = [MtrrMemoryRange::default();
        MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let mut expected_memory_ranges_count;

    let mut actual_memory_ranges = [MtrrMemoryRange::default();
        MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let mut actual_variable_mtrr_usage: u32;
    let mut actual_memory_ranges_count: usize;

    println!(
        "------------unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_empty_mtrr_settings begin------------"
    );
    println!("system_parameter: {system_parameter:?}");

    for (pattern_index, memory_type_counts) in
        memory_type_test_patterns(system_parameter.variable_mtrr_count).enumerate()
    {
        println!("--- Testing with pattern {} ---", pattern_index);

        let mut mtrrlib = MtrrTestFixture::new()
            .with_config(|_config| SystemParameterBuilder::from(system_parameter.clone()))
            .mtrr_lib();

        let mut pair_generator = MtrrPairGenerator::new(0);
        let generated_ranges = pair_generator.generate_multiple_pairs(
            system_parameter.physical_address_bits as u32 - system_parameter.mk_tme_keyid_bits as u32,
            memory_type_counts,
        );

        for (i, range) in generated_ranges.iter().enumerate() {
            if i < raw_mtrr_range.len() {
                raw_mtrr_range[i] = *range;
            }
        }

        let raw_mtrr_range_count = memory_type_counts.total();
        expected_memory_ranges_count = expected_memory_ranges.len();

        println!("--- Raw MTRR Range [{raw_mtrr_range_count}]---");
        dump_memory_ranges(&raw_mtrr_range, raw_mtrr_range_count as usize);

        get_effective_memory_ranges(
            system_parameter.default_cache_type,
            system_parameter.physical_address_bits as u32 - system_parameter.mk_tme_keyid_bits as u32,
            &raw_mtrr_range[..],
            raw_mtrr_range_count as usize,
            &mut expected_memory_ranges[..],
            &mut expected_memory_ranges_count,
        );

        println!("--- Expected Memory Ranges [{}] ---", expected_memory_ranges_count);
        dump_memory_ranges(&expected_memory_ranges, expected_memory_ranges_count);

        for index in 0..raw_mtrr_range_count as usize {
            println!("--------------------------------------------------");
            println!("--------------------------------------------------");
            println!("{index} calling set_memory_attribute");

            status = mtrrlib.set_memory_attribute(
                raw_mtrr_range[index].base_address,
                raw_mtrr_range[index].length,
                raw_mtrr_range[index].mem_type,
            );

            if status.is_err() {
                return;
            }
        }

        let mtrr_setting = mtrrlib.get_all_mtrrs().unwrap();

        let collector = TestResultCollector::new(
            system_parameter.default_cache_type,
            system_parameter.physical_address_bits as u32 - system_parameter.mk_tme_keyid_bits as u32,
            system_parameter.variable_mtrr_count,
        );
        let (result_ranges_count, result_variable_usage) =
            collector.collect_results(&mtrr_setting, &mut actual_memory_ranges);
        actual_memory_ranges_count = result_ranges_count;
        actual_variable_mtrr_usage = result_variable_usage;

        println!("--- Raw MTRR Range [{raw_mtrr_range_count}] ---");
        dump_memory_ranges(&raw_mtrr_range, raw_mtrr_range_count as usize);
        println!("--- Actual Memory Ranges [{actual_memory_ranges_count}] ---");
        dump_memory_ranges(&actual_memory_ranges, actual_memory_ranges_count);
        println!("--- Expected Memory Ranges [{expected_memory_ranges_count}] ---");
        dump_memory_ranges(&expected_memory_ranges, expected_memory_ranges_count);
        verify_memory_ranges(
            &expected_memory_ranges[..],
            expected_memory_ranges_count,
            &actual_memory_ranges,
            actual_memory_ranges_count,
        );
        assert!(raw_mtrr_range_count >= actual_variable_mtrr_usage);

        let returned_memory_ranges = mtrrlib.get_memory_ranges();
        assert!(returned_memory_ranges.is_ok());
        let returned_memory_ranges = returned_memory_ranges.unwrap();
        println!("--- Returned Memory Ranges [{}] ---", returned_memory_ranges.len());
        dump_memory_ranges(&returned_memory_ranges, returned_memory_ranges.len());
        verify_memory_ranges(
            &expected_memory_ranges,
            expected_memory_ranges_count,
            &returned_memory_ranges,
            returned_memory_ranges.len(),
        );
    }

    println!(
        "------------unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_empty_mtrr_settings end------------"
    );
}

#[test]
fn unit_test_mtrr_lib_usage() {
    const BASE_128KB: u64 = 0x20000;
    const BASE_512KB: u64 = 0x80000;
    const BASE_1MB: u64 = 0x100000;
    const BASE_4GB: u64 = 0x100000000;

    let mut mtrrlib = MtrrTestFixture::new()
        .with_config(|config| {
            config
                .with_physical_address_bits(38)
                .with_variable_mtrr_count(12)
                .with_default_cache_type(MtrrMemoryCacheType::Uncacheable)
        })
        .mtrr_lib();

    // Get the current MTRR settings
    let mut mtrr_settings = mtrrlib.get_all_mtrrs().unwrap();
    for index in 0..mtrr_settings.fixed.mtrr.len() {
        mtrr_settings.fixed.mtrr[index] = 0x0606060606060606;
    }
    mtrr_settings.mtrr_def_type_reg.set_mem_type(MtrrMemoryCacheType::WriteBack as u8);

    // Set the MTRR settings
    mtrrlib.set_all_mtrrs(&mtrr_settings);

    let status = mtrrlib.set_memory_attribute(
        BASE_512KB + BASE_128KB,
        BASE_1MB - (BASE_512KB + BASE_128KB),
        MtrrMemoryCacheType::Uncacheable,
    );
    assert!(status.is_ok());

    let status = mtrrlib.set_memory_attribute(0xB0000000, BASE_4GB - 0xB0000000, MtrrMemoryCacheType::Uncacheable);
    assert!(status.is_ok())
}
