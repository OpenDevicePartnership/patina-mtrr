use crate::{
    hal::HalTrait,
    structs::{
        MsrIa32MtrrDefType, MsrIa32MtrrPhysbaseRegister, MsrIa32MtrrPhysmaskRegister, MtrrFixedSettings,
        MtrrMemoryCacheType, MtrrMemoryRange, MtrrSettings, MtrrVariableSetting, MtrrVariableSettings,
        MSR_IA32_MTRR_DEF_TYPE, MSR_IA32_MTRR_PHYSBASE0, MSR_IA32_MTRR_PHYSMASK0, MTRR_NUMBER_OF_FIXED_MTRR,
        MTRR_NUMBER_OF_VARIABLE_MTRR,
    },
    tests::M_DEFAULT_SYSTEM_PARAMETER,
    utils::lshift_u64,
};
use crate::{
    tests::mock_hal::{create_mtrr_lib_with_mock_hal, MockHal},
    tests::support::{
        collect_test_result, generate_random_cache_type, generate_random_mtrr_pair,
        generate_valid_and_configurable_mtrr_pairs, get_effective_memory_ranges, random32, random64,
    },
    tests::{MtrrLibSystemParameter, M_FIXED_MTRRS_INDEX},
};
use rand::random;
use std::{panic, u32};

use super::M_SYSTEM_PARAMETERS;

//
//  Compare the actual memory ranges against expected memory ranges and return PASS when they match.
//
//  @param ExpectedMemoryRanges     Expected memory ranges.
//  @param ExpectedMemoryRangeCount Count of expected memory ranges.
//  @param ActualRanges             Actual memory ranges.
//  @param ActualRangeCount         Count of actual memory ranges.
//
//  @retval UNIT_TEST_PASSED  Test passed.
//  @retval others            Test failed.
//
fn verify_memory_ranges(
    expected_memory_ranges: &[MtrrMemoryRange],
    expected_memory_ranges_count: usize,
    actual_ranges: &[MtrrMemoryRange],
    actual_ranges_count: usize,
) {
    assert_eq!(expected_memory_ranges_count, actual_ranges_count);

    for index in 0..expected_memory_ranges_count {
        assert_eq!(expected_memory_ranges[index].base_address, actual_ranges[index].base_address);
        assert_eq!(expected_memory_ranges[index].length, actual_ranges[index].length);
        assert_eq!(expected_memory_ranges[index].mem_type, actual_ranges[index].mem_type);
    }
}

//
//  Dump the memory ranges.
//
//  @param Ranges       Memory ranges to dump.
//  @param RangeCount   Count of memory ranges.
//
fn dump_memory_ranges(ranges: &[MtrrMemoryRange], range_count: usize) {
    for index in 0..range_count {
        println!(
            "\t{{ [0x{:016x} - 0x{:016x}], 0x{:016x}, {:?} }},",
            ranges[index].base_address,
            ranges[index].base_address + ranges[index].length,
            ranges[index].length,
            ranges[index].mem_type
        );
    }
}

//
//  Generate random count of MTRRs for each cache type.
//
//  @param TotalCount Total MTRR count.
//  @param UcCount    Return count of Uncacheable type.
//  @param WtCount    Return count of Write Through type.
//  @param WbCount    Return count of Write Back type.
//  @param WpCount    Return count of Write Protected type.
//  @param WcCount    Return count of Write Combining type.
//
fn generate_random_memory_type_combination(
    total_count: u32,
    uc_count: &mut u32,
    wt_count: &mut u32,
    wb_count: &mut u32,
    wp_count: &mut u32,
    wc_count: &mut u32,
) {
    let mut count_per_type = [&mut *uc_count, &mut *wt_count, &mut *wb_count, &mut *wp_count, &mut *wc_count];

    // Initialize the count of each cache type to 0
    for count in count_per_type.iter_mut() {
        **count = 0;
    }

    // Pick a random count of MTRRs
    let total_mtrr_count = random::<u32>() % total_count + 1;
    for _ in 0..total_mtrr_count {
        // Pick a random cache type and increment its count
        let cache_type_index = random::<usize>() % count_per_type.len();
        *count_per_type[cache_type_index] += 1;
    }

    // Print the count of each cache type
    println!(
        "Total MTRR [{}]: UC={}, WT={}, WB={}, WP={}, WC={}",
        total_mtrr_count, *uc_count, *wt_count, *wb_count, *wp_count, *wc_count
    );
}

//
//  Unit test of MtrrLib service MtrrGetMemoryAttributesInMtrrSettings() and
//  MtrrSetMemoryAttributesInMtrrSettings()
//
//  @param[in]  Context    Ignored
//
//  @retval  UNIT_TEST_PASSED             The Unit test has completed and the test
//                                        case was successful.
//  @retval  UNIT_TEST_ERROR_TEST_FAILED  A test case assertion has failed.
//
//
// pub fn unit_test_mtrr_set_and_get_memory_attributes_in_mtrr_settings(system_parameter: &MtrrLibSystemParameter) {
//     let system_parameter = system_parameter;
//     let mut uc_count = 0;
//     let mut wt_count = 0;
//     let mut wb_count = 0;
//     let mut wp_count = 0;
//     let mut wc_count = 0;

//     let mut mtrr_index;
//     let mut scratch;
//     let mut scratch_size;
//     let mut local_mtrrs = MtrrSettings::default();

//     let mut raw_mtrr_range = vec![MtrrMemoryRange::default(); MTRR_NUMBER_OF_VARIABLE_MTRR];
//     let mut expected_memory_ranges =
//         vec![
//             MtrrMemoryRange::default();
//             MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1
//         ];
//     let mut raw_mtrr_range_count;
//     let mut expected_memory_ranges_count;

//     let mut actual_memory_ranges =
//         vec![
//             MtrrMemoryRange::default();
//             MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1
//         ];
//     let mut actual_variable_mtrr_usage;
//     let mut actual_memory_ranges_count;

//     let mut returned_memory_ranges =
//         vec![
//             MtrrMemoryRange::default();
//             MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1
//         ];
//     let mut returned_memory_ranges_count;

//     let mut mtrrs = vec![&mut local_mtrrs, &mut MtrrSettings::default()];

//     generate_random_memory_type_combination(
//         system_parameter.variable_mtrr_count - get_pcd_cpu_number_of_reserved_variable_mtrrs(),
//         &mut uc_count,
//         &mut wt_count,
//         &mut wb_count,
//         &mut wp_count,
//         &mut wc_count,
//     );
//     generate_valid_and_configurable_mtrr_pairs(
//         (system_parameter.physical_address_bits - system_parameter.mk_tme_keyid_bits) as u32,
//         &mut raw_mtrr_range,
//         uc_count,
//         wt_count,
//         wb_count,
//         wp_count,
//         wc_count,
//     );

//     raw_mtrr_range_count = uc_count + wt_count + wb_count + wp_count + wc_count;
//     expected_memory_ranges_count = expected_memory_ranges.len();
//     get_effective_memory_ranges(
//         system_parameter.default_cache_type,
//         (system_parameter.physical_address_bits - system_parameter.mk_tme_keyid_bits) as u32,
//         &raw_mtrr_range,
//         raw_mtrr_range_count as usize,
//         &mut expected_memory_ranges,
//         &mut expected_memory_ranges_count,
//     );

//     println!(
//         "Total MTRR [{}]: UC={}, WT={}, WB={}, WP={}, WC={}",
//         raw_mtrr_range_count, uc_count, wt_count, wb_count, wp_count, wc_count
//     );
//     println!("--- Expected Memory Ranges [{}] ---", expected_memory_ranges_count);
//     dump_memory_ranges(&expected_memory_ranges, expected_memory_ranges_count);

//     // Default cache type is always an INPUT
//     local_mtrrs.mtrr_def_type_reg = mtrr_get_default_memory_type() as u64;
//     scratch_size = SCRATCH_BUFFER_SIZE;
//     mtrrs[0] = &mut local_mtrrs;
//     mtrrs[1] = &mut MtrrSettings::default();

//     for mtrr_index in 0..mtrrs.len() {
//         scratch = vec![0u8; scratch_size];
//         let mut status = mtrr_set_memory_attributes_in_mtrr_settings(
//             Some(mtrrs[mtrr_index]),
//             &mut scratch,
//             &mut scratch_size,
//             &expected_memory_ranges,
//             expected_memory_ranges_count,
//         );
//         if status == RETURN_BUFFER_TOO_SMALL {
//             scratch.resize(scratch_size, 0);
//             println!("Not enough scratch space");
//             status = mtrr_set_memory_attributes_in_mtrr_settings(
//                 Some(mtrrs[mtrr_index]),
//                 &mut scratch,
//                 &mut scratch_size,
//                 &expected_memory_ranges,
//                 expected_memory_ranges_count,
//             );
//         }

//         assert!(status.is_ok());

//         if mtrrs[mtrr_index] == MtrrSettings::default() {
//             local_mtrrs = MtrrSettings::default();
//             mtrr_get_all_mtrrs(&mut local_mtrrs);
//         }

//         actual_memory_ranges_count = actual_memory_ranges.len();
//         collect_test_result(
//             system_parameter.default_cache_type,
//             system_parameter.physical_address_bits - system_parameter.mk_tme_keyid_bits,
//             system_parameter.variable_mtrr_count,
//             &local_mtrrs,
//             &mut actual_memory_ranges,
//             &mut actual_memory_ranges_count,
//             &mut actual_variable_mtrr_usage,
//         );

//         println!("--- Actual Memory Ranges [{}] ---", actual_memory_ranges_count);
//         dump_memory_ranges(&actual_memory_ranges, actual_memory_ranges_count);
//         verify_memory_ranges(
//             &expected_memory_ranges,
//             expected_memory_ranges_count,
//             &actual_memory_ranges,
//             actual_memory_ranges_count,
//         );
//         assert!(raw_mtrr_range_count >= actual_variable_mtrr_usage);

//         returned_memory_ranges_count = returned_memory_ranges.len();
//         status = mtrr_get_memory_ranges(
//             mtrrs[mtrr_index],
//             &mut returned_memory_ranges,
//             &mut returned_memory_ranges_count,
//         );
//         assert!(status.is_ok());
//         println!("--- Returned Memory Ranges [{}] ---", returned_memory_ranges_count);
//         dump_memory_ranges(&returned_memory_ranges, returned_memory_ranges_count);
//         verify_memory_ranges(
//             &expected_memory_ranges,
//             expected_memory_ranges_count,
//             &returned_memory_ranges,
//             returned_memory_ranges_count,
//         );

//         local_mtrrs = MtrrSettings::default();
//     }
// }

fn set_randomly_generated_mtrr_settings(
    hal: &mut MockHal,
    system_parameter: &MtrrLibSystemParameter,
    expected_mtrrs: &mut MtrrSettings,
) {
    // Set Default MTRR Type
    hal.asm_write_msr64(MSR_IA32_MTRR_DEF_TYPE, expected_mtrrs.mtrr_def_type_reg.into_bits());

    // Randomly generate Variable MTRR BASE/MASK for a specified type and write to MSR
    for index in 0..system_parameter.variable_mtrr_count {
        let mut pair = MtrrVariableSetting::default();
        generate_random_mtrr_pair(
            system_parameter.physical_address_bits as u32,
            generate_random_cache_type(),
            Some(&mut pair),
            None,
        );
        expected_mtrrs.variables.mtrr[index as usize].base = pair.base;
        expected_mtrrs.variables.mtrr[index as usize].mask = pair.mask;
        hal.asm_write_msr64(MSR_IA32_MTRR_PHYSBASE0 + (index << 1), pair.base);
        hal.asm_write_msr64(MSR_IA32_MTRR_PHYSMASK0 + (index << 1), pair.mask);
    }

    // Set Fixed MTRRs when the Fixed MTRRs is enabled and the MTRRs is supported
    let default = MsrIa32MtrrDefType::from(hal.asm_read_msr64(MSR_IA32_MTRR_DEF_TYPE));
    if default.fe() && system_parameter.mtrr_supported {
        for msr_index in 0..M_FIXED_MTRRS_INDEX.len() {
            let mut msr_value = 0u64;
            for byte_index in 0..8 {
                msr_value |= (generate_random_cache_type() as u64) << (byte_index * 8);
            }
            expected_mtrrs.fixed.mtrr[msr_index] = msr_value;
            hal.asm_write_msr64(M_FIXED_MTRRS_INDEX[msr_index], msr_value);
        }
    }
}

// Unit tests

#[test]
fn unit_test_is_mtrr_supported() {
    // Default system parameter
    let mut system_parameter: MtrrLibSystemParameter = M_DEFAULT_SYSTEM_PARAMETER.clone();

    // MTRR capability off in CPUID leaf.
    system_parameter.mtrr_supported = false;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    assert!(!mtrrlib.is_mtrr_supported());

    // MTRR capability on in CPUID leaf, but no variable or fixed MTRRs.
    system_parameter.mtrr_supported = true;
    system_parameter.variable_mtrr_count = 0;
    system_parameter.fixed_mtrr_supported = false;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    assert!(!mtrrlib.is_mtrr_supported());

    // MTRR capability on in CPUID leaf, but no variable MTRRs.
    system_parameter.mtrr_supported = true;
    system_parameter.variable_mtrr_count = 0;
    system_parameter.fixed_mtrr_supported = true;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    assert!(mtrrlib.is_mtrr_supported());

    // MTRR capability on in CPUID leaf, but no fixed MTRRs.
    system_parameter.mtrr_supported = true;
    system_parameter.variable_mtrr_count = 7;
    system_parameter.fixed_mtrr_supported = false;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    assert!(mtrrlib.is_mtrr_supported());

    // MTRR capability on in CPUID leaf with both variable and fixed MTRRs.
    system_parameter.mtrr_supported = true;
    system_parameter.variable_mtrr_count = 7;
    system_parameter.fixed_mtrr_supported = true;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    assert!(mtrrlib.is_mtrr_supported());
}

#[test]
fn unit_test_get_variable_mtrr_count() {
    // Default system parameter
    let mut system_parameter: MtrrLibSystemParameter = M_DEFAULT_SYSTEM_PARAMETER.clone();

    // If MTRR capability off in CPUID leaf, then the count is always 0.
    system_parameter.mtrr_supported = false;
    system_parameter.variable_mtrr_count = 1;
    while system_parameter.variable_mtrr_count <= MTRR_NUMBER_OF_VARIABLE_MTRR as u32 {
        let mut hal = MockHal::new();
        hal.initialize_mtrr_regs(&system_parameter);
        let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
        let res = mtrrlib.get_variable_mtrr_count();
        assert_eq!(res, 0);
        system_parameter.variable_mtrr_count += 1;
    }

    // Try all supported variable MTRR counts.
    // If variable MTRR count is > MTRR_NUMBER_OF_VARIABLE_MTRR, then an ASSERT()
    // is generated.
    system_parameter.mtrr_supported = true;
    system_parameter.variable_mtrr_count = 1;
    while system_parameter.variable_mtrr_count <= MTRR_NUMBER_OF_VARIABLE_MTRR as u32 {
        let mut hal = MockHal::new();
        hal.initialize_mtrr_regs(&system_parameter);
        let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
        let res = mtrrlib.get_variable_mtrr_count();
        assert_eq!(res, system_parameter.variable_mtrr_count);
        system_parameter.variable_mtrr_count += 1;
    }

    // Expect ASSERT() if variable MTRR count is > MTRR_NUMBER_OF_VARIABLE_MTRR
    system_parameter.variable_mtrr_count = MTRR_NUMBER_OF_VARIABLE_MTRR as u32 + 1;
    let _ = panic::catch_unwind(|| {
        let mut hal = MockHal::new();
        hal.initialize_mtrr_regs(&system_parameter);
        let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
        let _ = mtrrlib.get_variable_mtrr_count();
    });

    system_parameter.mtrr_supported = true;
    system_parameter.variable_mtrr_count = 0xFF;
    let _ = panic::catch_unwind(|| {
        let mut hal = MockHal::new();
        hal.initialize_mtrr_regs(&system_parameter);
        let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
        let _ = mtrrlib.get_variable_mtrr_count();
    });
}

#[test]
fn unit_test_get_firmware_variable_mtrr_count() {
    // Default system parameter
    let mut system_parameter: MtrrLibSystemParameter = M_DEFAULT_SYSTEM_PARAMETER.clone();

    // Positive test cases for VCNT = 10 and Reserved PCD in range 0..10
    for reserved_mtrr in 0..=system_parameter.variable_mtrr_count {
        let mut hal = MockHal::new();
        hal.initialize_mtrr_regs(&system_parameter);
        hal.set_pcd_cpu_number_of_reserved_variable_mtrrs(reserved_mtrr);
        let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
        let res = mtrrlib.get_firmware_usable_variable_mtrr_count();
        assert_eq!(res, system_parameter.variable_mtrr_count - reserved_mtrr);
    }

    // Negative test cases when Reserved PCD is larger than VCNT
    for reserved_mtrr in system_parameter.variable_mtrr_count + 1..255 {
        let mut hal = MockHal::new();
        hal.initialize_mtrr_regs(&system_parameter);
        hal.set_pcd_cpu_number_of_reserved_variable_mtrrs(reserved_mtrr);
        let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
        let res = mtrrlib.get_firmware_usable_variable_mtrr_count();
        assert_eq!(res, 0);
    }

    // Negative test cases when Reserved PCD is larger than VCNT
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    hal.set_pcd_cpu_number_of_reserved_variable_mtrrs(u32::MAX);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    let res = mtrrlib.get_firmware_usable_variable_mtrr_count();
    assert_eq!(res, 0);

    // Negative test case when MTRRs are not supported
    system_parameter.mtrr_supported = false;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    hal.set_pcd_cpu_number_of_reserved_variable_mtrrs(2);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    let res = mtrrlib.get_firmware_usable_variable_mtrr_count();
    assert_eq!(res, 0);

    // Negative test case when Fixed MTRRs are not supported
    system_parameter.mtrr_supported = true;
    system_parameter.fixed_mtrr_supported = false;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    hal.set_pcd_cpu_number_of_reserved_variable_mtrrs(2);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    let res = mtrrlib.get_firmware_usable_variable_mtrr_count();
    assert_eq!(res, system_parameter.variable_mtrr_count - 2);

    // Expect ASSERT() if variable MTRR count is > MTRR_NUMBER_OF_VARIABLE_MTRR
    system_parameter.fixed_mtrr_supported = true;
    system_parameter.variable_mtrr_count = MTRR_NUMBER_OF_VARIABLE_MTRR as u32 + 1;
    let _ = panic::catch_unwind(|| {
        let mut hal = MockHal::new();
        hal.initialize_mtrr_regs(&system_parameter);
        hal.set_pcd_cpu_number_of_reserved_variable_mtrrs(2);
        let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
        let _ = mtrrlib.get_firmware_usable_variable_mtrr_count();
    });
}

#[test]
fn unit_test_mtrr_get_fixed_mtrr() {
    // Default system parameter
    let mut system_parameter: MtrrLibSystemParameter = M_DEFAULT_SYSTEM_PARAMETER.clone();

    // Set random cache type to different ranges under 1MB and make sure
    // the fixed MTRR settings are expected.
    // Try 100 times.
    let mut expected_mtrr_fixed_settings = MtrrFixedSettings::default();
    for _ in 0..100 {
        let mut hal = MockHal::new();
        hal.initialize_mtrr_regs(&system_parameter);
        for msr_index in 0..MTRR_NUMBER_OF_FIXED_MTRR {
            let mut msr_value = 0;
            for byte in 0..8 {
                let mem_type = generate_random_cache_type();
                msr_value |= lshift_u64(mem_type as u8 as u64, byte * 8)
            }

            expected_mtrr_fixed_settings.mtrr[msr_index] = msr_value;
            hal.asm_write_msr64(M_FIXED_MTRRS_INDEX[msr_index], msr_value);
        }
        let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
        let fixed_settings = mtrrlib.mtrr_get_fixed_mtrr();
        assert!(fixed_settings.mtrr == expected_mtrr_fixed_settings.mtrr)
    }

    // Negative test case when MTRRs are not supported
    system_parameter.mtrr_supported = false;
    let expected_mtrr_fixed_settings = MtrrFixedSettings::default();
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    let fixed_settings = mtrrlib.mtrr_get_fixed_mtrr();
    assert!(fixed_settings.mtrr == expected_mtrr_fixed_settings.mtrr);

    // Negative test case when Fixed MTRRs are not supported
    system_parameter.mtrr_supported = true;
    system_parameter.fixed_mtrr_supported = false;
    let expected_mtrr_fixed_settings = MtrrFixedSettings::default();
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    let fixed_settings = mtrrlib.mtrr_get_fixed_mtrr();
    assert!(fixed_settings.mtrr == expected_mtrr_fixed_settings.mtrr);
}

#[test]
fn unit_test_mtrr_get_all_mtrrs() {
    // Default system parameter
    let mut system_parameter: MtrrLibSystemParameter = M_DEFAULT_SYSTEM_PARAMETER.clone();

    // For the case that Fixed MTRRs is NOT enabled
    system_parameter.mtrr_supported = true;
    system_parameter.fixed_mtrr_supported = false;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mut expected_mtrr_settings = MtrrSettings::default();
    expected_mtrr_settings.mtrr_def_type_reg = MsrIa32MtrrDefType::default().with_e(true).with_fe(false);
    set_randomly_generated_mtrr_settings(&mut hal, &system_parameter, &mut expected_mtrr_settings);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    let mtrr_settings = mtrrlib.mtrr_get_all_mtrrs();
    assert!(mtrr_settings.fixed == expected_mtrr_settings.fixed);
    assert!(mtrr_settings.variables == expected_mtrr_settings.variables);

    // For the case that Fixed MTRRs is enabled
    system_parameter.mtrr_supported = true;
    system_parameter.fixed_mtrr_supported = true;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mut expected_mtrr_settings = MtrrSettings::default();
    expected_mtrr_settings.mtrr_def_type_reg = MsrIa32MtrrDefType::default().with_e(true).with_fe(true);
    set_randomly_generated_mtrr_settings(&mut hal, &system_parameter, &mut expected_mtrr_settings);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    let mtrr_settings = mtrrlib.mtrr_get_all_mtrrs();
    assert!(mtrr_settings.fixed == expected_mtrr_settings.fixed);
    assert!(mtrr_settings.variables == expected_mtrr_settings.variables);

    // Negative test case when MTRRs are not supported
    system_parameter.mtrr_supported = false;
    system_parameter.fixed_mtrr_supported = true;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mut expected_mtrr_settings = MtrrSettings::default();
    expected_mtrr_settings.mtrr_def_type_reg = MsrIa32MtrrDefType::default().with_e(true).with_fe(true);
    // set_randomly_generated_mtrr_settings(&mut hal, &system_parameter, &mut expected_mtrr_settings);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    let mtrr_settings = mtrrlib.mtrr_get_all_mtrrs();
    assert!(mtrr_settings.fixed == expected_mtrr_settings.fixed);
    assert!(mtrr_settings.variables == expected_mtrr_settings.variables);

    // Expect ASSERT() if variable MTRR count is > MTRR_NUMBER_OF_VARIABLE_MTRR
    system_parameter.mtrr_supported = true;
    system_parameter.variable_mtrr_count = MTRR_NUMBER_OF_VARIABLE_MTRR as u32 + 1;
    let _ = panic::catch_unwind(|| {
        let mut hal = MockHal::new();
        hal.initialize_mtrr_regs(&system_parameter);
        let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
        let _ = mtrrlib.mtrr_get_all_mtrrs();
    });
}

#[test]
fn unit_test_mtrr_set_all_mtrrs() {
    // Default system parameter
    let system_parameter: MtrrLibSystemParameter =
        MtrrLibSystemParameter::new(42, true, true, MtrrMemoryCacheType::Uncacheable, 12, 0);

    let mut expected_mtrr_settings = MtrrSettings::default();
    let mem_type: u8 = generate_random_cache_type() as u8;
    expected_mtrr_settings.mtrr_def_type_reg =
        MsrIa32MtrrDefType::default().with_e(true).with_fe(false).with_mem_type(mem_type);

    // Randomly generate Variable MTRR BASE/MASK for a specified type and write to MSR
    for index in 0..system_parameter.variable_mtrr_count {
        let mut pair = MtrrVariableSetting::default();
        generate_random_mtrr_pair(
            system_parameter.physical_address_bits as u32,
            generate_random_cache_type(),
            Some(&mut pair),
            None,
        );
        expected_mtrr_settings.variables.mtrr[index as usize].base = pair.base;
        expected_mtrr_settings.variables.mtrr[index as usize].mask = pair.mask;
    }

    for msr_index in 0..MTRR_NUMBER_OF_FIXED_MTRR {
        let mut msr_value = 0;
        for byte in 0..8 {
            let mem_type = generate_random_cache_type();
            msr_value |= lshift_u64(mem_type as u8 as u64, byte * 8)
        }

        expected_mtrr_settings.fixed.mtrr[msr_index] = msr_value;
    }

    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mut mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    mtrrlib.mtrr_set_all_mtrrs(&expected_mtrr_settings);

    // we need access the hal to cross verify the MSR values. Hence we need to
    // drop it from mtrrlib
    let hal = mtrrlib.mtrr_drop_hal();

    assert_eq!(hal.asm_read_msr64(MSR_IA32_MTRR_DEF_TYPE), expected_mtrr_settings.mtrr_def_type_reg.into_bits());
    for index in 0..system_parameter.variable_mtrr_count {
        assert_eq!(
            hal.asm_read_msr64(MSR_IA32_MTRR_PHYSBASE0 + (index * 2)),
            expected_mtrr_settings.variables.mtrr[index as usize].base
        );
        assert_eq!(
            hal.asm_read_msr64(MSR_IA32_MTRR_PHYSMASK0 + (index * 2)),
            expected_mtrr_settings.variables.mtrr[index as usize].mask
        );
    }
}

#[test]
fn unit_test_mtrr_get_memory_attribute_in_variable_mtrr() {
    // Default system parameter
    let mut system_parameter: MtrrLibSystemParameter = M_DEFAULT_SYSTEM_PARAMETER.clone();

    let mut expected_mtrr_settings = MtrrSettings::default();
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    // Randomly generate Variable MTRR BASE/MASK for a specified type and write to MSR
    for index in 0..system_parameter.variable_mtrr_count {
        let mut pair = MtrrVariableSetting::default();
        generate_random_mtrr_pair(
            system_parameter.physical_address_bits as u32,
            generate_random_cache_type(),
            Some(&mut pair),
            None,
        );
        expected_mtrr_settings.variables.mtrr[index as usize].base = pair.base;
        expected_mtrr_settings.variables.mtrr[index as usize].mask = pair.mask;
        hal.asm_write_msr64(MSR_IA32_MTRR_PHYSBASE0 + (index << 1), pair.base);
        hal.asm_write_msr64(MSR_IA32_MTRR_PHYSMASK0 + (index << 1), pair.mask);
    }

    let valid_mtrr_bits_mask: u64;
    let valid_mtrr_address_mask: u64;
    valid_mtrr_bits_mask = (1u64 << system_parameter.physical_address_bits) - 1;
    valid_mtrr_address_mask = valid_mtrr_bits_mask & 0xfffffffffffff000;
    // println!("valid_mtrr_bits_mask: {:x}", valid_mtrr_bits_mask);
    // println!("valid_mtrr_address_mask: {:x}", valid_mtrr_address_mask);

    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    let variable_mtrr =
        mtrrlib.mtrr_get_memory_attribute_in_variable_mtrr(valid_mtrr_bits_mask, valid_mtrr_address_mask);

    for index in 0..system_parameter.variable_mtrr_count as usize {
        let base = MsrIa32MtrrPhysbaseRegister::default()
            .with_phys_base((variable_mtrr[index].base_address & valid_mtrr_address_mask) >> 12)
            .with_mem_type(variable_mtrr[index].mem_type)
            .into_bits();

        assert_eq!(base, expected_mtrr_settings.variables.mtrr[index].base);

        let mask = MsrIa32MtrrPhysmaskRegister::default()
            .with_phys_mask(((!(variable_mtrr[index].length - 1)) & valid_mtrr_bits_mask) >> 12)
            .with_v(true)
            .into_bits();

        assert_eq!(mask, expected_mtrr_settings.variables.mtrr[index].mask);
    }

    // Negative test case when MTRRs are not supported
    system_parameter.mtrr_supported = false;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    let variable_mtrr =
        mtrrlib.mtrr_get_memory_attribute_in_variable_mtrr(valid_mtrr_bits_mask, valid_mtrr_address_mask);
    assert!(variable_mtrr.len() <= MTRR_NUMBER_OF_VARIABLE_MTRR);
    assert!(variable_mtrr.len() <= mtrrlib.get_firmware_usable_variable_mtrr_count() as usize);

    // Expect ASSERT() if variable MTRR count is > MTRR_NUMBER_OF_VARIABLE_MTRR
    system_parameter.mtrr_supported = true;
    system_parameter.variable_mtrr_count = MTRR_NUMBER_OF_VARIABLE_MTRR as u32 + 1;
    let _ = panic::catch_unwind(|| {
        let mut hal = MockHal::new();
        hal.initialize_mtrr_regs(&system_parameter);
        let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
        let _variable_mtrr = mtrrlib.mtrr_get_memory_attribute_in_variable_mtrr(
            valid_mtrr_bits_mask,
            valid_mtrr_address_mask,
            // &mut variable_mtrr[..],
        );
    });
}

#[test]
fn unit_test_mtrr_get_default_memory_type() {
    // Default system parameter
    let mut system_parameter: MtrrLibSystemParameter = M_DEFAULT_SYSTEM_PARAMETER.clone();

    let cache_types = [
        MtrrMemoryCacheType::Uncacheable,
        MtrrMemoryCacheType::WriteCombining,
        MtrrMemoryCacheType::WriteThrough,
        MtrrMemoryCacheType::WriteProtected,
        MtrrMemoryCacheType::WriteBack,
    ];

    for &cache_type in &cache_types {
        system_parameter.default_cache_type = cache_type;
        let mut hal = MockHal::new();
        hal.initialize_mtrr_regs(&system_parameter);
        let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
        let result = mtrrlib.mtrr_get_default_memory_type();
        assert_eq!(result, system_parameter.default_cache_type);
    }

    // If MTRRs are not supported, then always return CacheUncacheable
    system_parameter.mtrr_supported = false;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    let result = mtrrlib.mtrr_get_default_memory_type();
    assert_eq!(result, MtrrMemoryCacheType::Uncacheable);

    // If MTRRs are supported, but Fixed MTRRs are not supported
    system_parameter.mtrr_supported = true;
    system_parameter.fixed_mtrr_supported = false;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    let result = mtrrlib.mtrr_get_default_memory_type();
    assert_eq!(result, system_parameter.default_cache_type);

    // If MTRRs are supported, but Variable MTRRs are not supported
    system_parameter.mtrr_supported = true;
    system_parameter.fixed_mtrr_supported = true;
    system_parameter.variable_mtrr_count = 0;
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);
    let mtrrlib = create_mtrr_lib_with_mock_hal(hal);
    let result = mtrrlib.mtrr_get_default_memory_type();
    assert_eq!(result, system_parameter.default_cache_type);
}

#[test]
fn unit_test_invalid_memory_layouts() {
    let iterations = 1;
    for system_parameter in &M_SYSTEM_PARAMETERS {
        for i in 0..iterations {
            println!("Iteration: {}", i);
            unit_test_invalid_memory_layouts_impl(system_parameter);
        }
    }
}

fn unit_test_invalid_memory_layouts_impl(system_parameter: &MtrrLibSystemParameter) {
    let mut ranges = [MtrrMemoryRange::default(); MTRR_NUMBER_OF_VARIABLE_MTRR * 2 + 1];
    let range_count: u32;
    let max_address: u64;
    let mut base_address: u64;
    let mut length: u64;

    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(system_parameter);
    let mut mtrrlib = create_mtrr_lib_with_mock_hal(hal);

    range_count = random32(1, ranges.len() as u32);
    max_address = 1u64 << (system_parameter.physical_address_bits - system_parameter.mk_tme_keyid_bits);

    for index in 0..range_count {
        loop {
            base_address = random64(0, max_address);
            length = random64(1, max_address - base_address);
            if (base_address & 0xFFF) != 0 && (length & 0xFFF) != 0 {
                break;
            }
        }

        ranges[index as usize].base_address = base_address;
        ranges[index as usize].length = length;
        ranges[index as usize].mem_type = generate_random_cache_type();

        let status = mtrrlib.mtrr_set_memory_attribute(
            ranges[index as usize].base_address,
            ranges[index as usize].length,
            ranges[index as usize].mem_type,
        );
        assert!(status.is_err());
    }

    for range in &ranges {
        let status = mtrrlib.mtrr_set_memory_attribute(range.base_address, range.length, range.mem_type);
        assert!(status.is_err());
    }
}

#[test]
fn unit_test_mtrr_set_memory_attribute_and_get_memory_attributes() {
    // let system_parameters = [
    // MtrrLibSystemParameter::new(38, true, true, MtrrMemoryCacheType::Uncacheable, 12, 0),
    //     // MtrrLibSystemParameter::new(38, true, true, MtrrMemoryCacheType::WriteBack, 12, 0),
    //     // MtrrLibSystemParameter::new(38, true, true, MtrrMemoryCacheType::WriteThrough, 12, 0),
    //     // MtrrLibSystemParameter::new(38, true, true, MtrrMemoryCacheType::WriteProtected, 12, 0),
    //     // MtrrLibSystemParameter::new(38, true, true, MtrrMemoryCacheType::WriteCombining, 12, 0),
    //     // MtrrLibSystemParameter::new(42, true, true, MtrrMemoryCacheType::Uncacheable, 12, 0),
    //     // MtrrLibSystemParameter::new(42, true, true, MtrrMemoryCacheType::WriteBack, 12, 0),
    //     // MtrrLibSystemParameter::new(42, true, true, MtrrMemoryCacheType::WriteThrough, 12, 0),
    //     // MtrrLibSystemParameter::new(42, true, true, MtrrMemoryCacheType::WriteProtected, 12, 0),
    //     // MtrrLibSystemParameter::new(42, true, true, MtrrMemoryCacheType::WriteCombining, 12, 0),
    //     // MtrrLibSystemParameter::new(48, true, true, MtrrMemoryCacheType::Uncacheable, 12, 0),
    //     MtrrLibSystemParameter::new(48, true, true, MtrrMemoryCacheType::WriteBack, 12, 0),
    //     // MtrrLibSystemParameter::new(48, true, true, MtrrMemoryCacheType::WriteThrough, 12, 0),
    //     // MtrrLibSystemParameter::new(48, true, true, MtrrMemoryCacheType::WriteProtected, 12, 0),
    //     // MtrrLibSystemParameter::new(48, true, true, MtrrMemoryCacheType::WriteCombining, 12, 0),
    //     // MtrrLibSystemParameter::new(48, true, false, MtrrMemoryCacheType::Uncacheable, 12, 0),
    //     // MtrrLibSystemParameter::new(48, true, false, MtrrMemoryCacheType::WriteBack, 12, 0),
    //     // MtrrLibSystemParameter::new(48, true, false, MtrrMemoryCacheType::WriteThrough, 12, 0),
    //     // MtrrLibSystemParameter::new(48, true, false, MtrrMemoryCacheType::WriteProtected, 12, 0),
    //     // MtrrLibSystemParameter::new(48, true, false, MtrrMemoryCacheType::WriteCombining, 12, 0),
    //     // MtrrLibSystemParameter::new(48, true, true, MtrrMemoryCacheType::WriteBack, 12, 7),
    // ];

    let iterations = 1;
    for system_parameter in &M_SYSTEM_PARAMETERS {
        for i in 0..iterations {
            println!("Iteration: {}", i);
            unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_mtrr_settings(system_parameter);
            unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_empty_mtrr_settings(system_parameter);
        }
    }
}

fn unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_mtrr_settings(
    system_parameter: &MtrrLibSystemParameter,
) {
    let mut status;
    let mut uc_count: u32 = 0;
    let mut wt_count: u32 = 0;
    let mut wb_count: u32 = 0;
    let mut wp_count: u32 = 0;
    let mut wc_count: u32 = 0;

    // let mut local_mtrrs = MtrrSettings::default();
    let mut raw_mtrr_range = [MtrrMemoryRange::default(); MTRR_NUMBER_OF_VARIABLE_MTRR];
    let mut expected_memory_ranges = [MtrrMemoryRange::default();
        MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let raw_mtrr_range_count: u32;
    let mut expected_memory_ranges_count;

    let mut actual_memory_ranges = [MtrrMemoryRange::default();
        MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let mut actual_variable_mtrr_usage: u32 = 0;
    let mut actual_memory_ranges_count: usize;

    let mut returned_memory_ranges = [MtrrMemoryRange::default();
        MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let mut returned_memory_ranges_count: usize;

    println!(
        "------------unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_mtrr_settings begin------------"
    );
    println!("system_parameter: {:?}", system_parameter);

    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(system_parameter);
    let pcd_cpu_number_of_reserved_variable_mtrrs = hal.get_pcd_cpu_number_of_reserved_variable_mtrrs();
    let mut mtrrlib = create_mtrr_lib_with_mock_hal(hal);

    generate_random_memory_type_combination(
        system_parameter.variable_mtrr_count - pcd_cpu_number_of_reserved_variable_mtrrs,
        &mut uc_count,
        &mut wt_count,
        &mut wb_count,
        &mut wp_count,
        &mut wc_count,
    );

    generate_valid_and_configurable_mtrr_pairs(
        system_parameter.physical_address_bits as u32 - system_parameter.mk_tme_keyid_bits as u32,
        &mut raw_mtrr_range,
        uc_count,
        wt_count,
        wb_count,
        wp_count,
        wc_count,
    );

    raw_mtrr_range_count = uc_count + wt_count + wb_count + wp_count + wc_count;
    expected_memory_ranges_count = expected_memory_ranges.len() as usize;

    // //     // TESTCODE BEGIN
    // let raw_mtrr_range: [MtrrMemoryRange; 9] = [
    //     MtrrMemoryRange::new(0x0000f00000000000, 0x0000004000000000, MtrrMemoryCacheType::Uncacheable),
    //     MtrrMemoryRange::new(0x0000efcc00000000, 0x0000000020000000, MtrrMemoryCacheType::Uncacheable),
    //     MtrrMemoryRange::new(0x0000e70000000000, 0x0000000000800000, MtrrMemoryCacheType::Uncacheable),
    //     MtrrMemoryRange::new(0x000073c000000000, 0x0000000010000000, MtrrMemoryCacheType::Uncacheable),
    //     MtrrMemoryRange::new(0x0000800000000000, 0x0000800000000000, MtrrMemoryCacheType::WriteThrough),
    //     MtrrMemoryRange::new(0x0000400000000000, 0x0000100000000000, MtrrMemoryCacheType::WriteThrough),
    //     MtrrMemoryRange::new(0x0000800000000000, 0x0000100000000000, MtrrMemoryCacheType::WriteBack),
    //     MtrrMemoryRange::new(0x0000060000000000, 0x0000004000000000, MtrrMemoryCacheType::WriteBack),
    //     MtrrMemoryRange::new(0x0000600000000000, 0x0000080000000000, MtrrMemoryCacheType::WriteCombining),
    //     ];
    //   let raw_mtrr_range_count = raw_mtrr_range.len() as u32;
    // //     // TESTCODE end

    println!("--- Raw MTRR Range [{}]---", raw_mtrr_range_count);
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

    let default_mem_type = system_parameter.default_cache_type as u8;
    let default_mem_type_reg = MsrIa32MtrrDefType::default().with_mem_type(default_mem_type as u8);

    let mtrr_setting =
        MtrrSettings::new(MtrrFixedSettings::default(), MtrrVariableSettings::default(), default_mem_type_reg);
    mtrrlib.mtrr_set_all_mtrrs(&mtrr_setting);
    for index in 0..expected_memory_ranges_count {
        println!("--------------------------------------------------");
        println!("--------------------------------------------------");
        println!("{} calling mtrr_set_memory_attribute", index);

        // println!("Before: \n{}", mtrr_setting);
        status = mtrrlib.mtrr_set_memory_attribute(
            expected_memory_ranges[index].base_address,
            expected_memory_ranges[index].length,
            expected_memory_ranges[index].mem_type,
        );
        // println!("After: \n{}", mtrr_setting);

        if status.is_err() {
            return;
        }
    }

    actual_memory_ranges_count = actual_memory_ranges.len();
    let mtrr_setting = mtrrlib.mtrr_get_all_mtrrs();
    collect_test_result(
        system_parameter.default_cache_type,
        system_parameter.physical_address_bits as u32 - system_parameter.mk_tme_keyid_bits as u32,
        system_parameter.variable_mtrr_count,
        &mtrr_setting,
        &mut actual_memory_ranges,
        &mut actual_memory_ranges_count,
        &mut actual_variable_mtrr_usage,
    );

    println!("--- System Parameter --- \n{:?}", system_parameter);
    println!("--- Raw MTRR Range [{}]---", raw_mtrr_range_count);
    dump_memory_ranges(&raw_mtrr_range, raw_mtrr_range_count as usize);
    println!("--- Actual Memory Ranges [{}] ---", actual_memory_ranges_count);
    dump_memory_ranges(&actual_memory_ranges, actual_memory_ranges_count);
    println!("--- Expected Memory Ranges [{}] ---", expected_memory_ranges_count);
    dump_memory_ranges(&expected_memory_ranges, expected_memory_ranges_count);
    verify_memory_ranges(
        &expected_memory_ranges[..],
        expected_memory_ranges_count,
        &actual_memory_ranges,
        actual_memory_ranges_count,
    );
    assert!(raw_mtrr_range_count >= actual_variable_mtrr_usage);

    returned_memory_ranges_count = returned_memory_ranges.len();
    status = mtrrlib.mtrr_get_memory_ranges(&mut returned_memory_ranges[..], Some(&mut returned_memory_ranges_count));
    assert!(status.is_ok());
    println!("--- Returned Memory Ranges [{}] ---", returned_memory_ranges_count);
    dump_memory_ranges(&returned_memory_ranges, returned_memory_ranges_count);
    verify_memory_ranges(
        &expected_memory_ranges,
        expected_memory_ranges_count,
        &returned_memory_ranges,
        returned_memory_ranges_count,
    );

    println!(
        "------------unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_mtrr_settings end------------"
    );
}

fn unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_empty_mtrr_settings(
    system_parameter: &MtrrLibSystemParameter,
) {
    let mut status;
    let mut uc_count: u32 = 0;
    let mut wt_count: u32 = 0;
    let mut wb_count: u32 = 0;
    let mut wp_count: u32 = 0;
    let mut wc_count: u32 = 0;

    // let mut local_mtrrs = MtrrSettings::default();
    let mut raw_mtrr_range = [MtrrMemoryRange::default(); MTRR_NUMBER_OF_VARIABLE_MTRR];
    let mut expected_memory_ranges = [MtrrMemoryRange::default();
        MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let raw_mtrr_range_count: u32;
    let mut expected_memory_ranges_count;

    let mut actual_memory_ranges = [MtrrMemoryRange::default();
        MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let mut actual_variable_mtrr_usage: u32 = 0;
    let mut actual_memory_ranges_count: usize;

    let mut returned_memory_ranges = [MtrrMemoryRange::default();
        MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let mut returned_memory_ranges_count: usize;

    println!(
        "------------unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_empty_mtrr_settings begin------------"
    );
    println!("system_parameter: {:?}", system_parameter);

    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(system_parameter);
    let pcd_cpu_number_of_reserved_variable_mtrrs = hal.get_pcd_cpu_number_of_reserved_variable_mtrrs();
    let mut mtrrlib = create_mtrr_lib_with_mock_hal(hal);

    generate_random_memory_type_combination(
        system_parameter.variable_mtrr_count - pcd_cpu_number_of_reserved_variable_mtrrs,
        &mut uc_count,
        &mut wt_count,
        &mut wb_count,
        &mut wp_count,
        &mut wc_count,
    );

    generate_valid_and_configurable_mtrr_pairs(
        system_parameter.physical_address_bits as u32 - system_parameter.mk_tme_keyid_bits as u32,
        &mut raw_mtrr_range,
        uc_count,
        wt_count,
        wb_count,
        wp_count,
        wc_count,
    );

    raw_mtrr_range_count = uc_count + wt_count + wb_count + wp_count + wc_count;
    expected_memory_ranges_count = expected_memory_ranges.len() as usize;

    //     // TESTCODE BEGIN
    // let raw_mtrr_range: [MtrrMemoryRange; 12] = [
    //     MtrrMemoryRange::new(0x0000800000000000, 0x0000200000000000, MtrrMemoryCacheType::Uncacheable),
    //     MtrrMemoryRange::new(0x0000589840960000, 0x0000000000002000, MtrrMemoryCacheType::Uncacheable),
    //     MtrrMemoryRange::new(0x0000180000000000, 0x0000000010000000, MtrrMemoryCacheType::Uncacheable),
    //     MtrrMemoryRange::new(0x0000800000000000, 0x0000000040000000, MtrrMemoryCacheType::Uncacheable),
    //     MtrrMemoryRange::new(0x0000b80000000000, 0x0000000010000000, MtrrMemoryCacheType::WriteThrough),
    //     MtrrMemoryRange::new(0x0000630000000000, 0x0000000002000000, MtrrMemoryCacheType::WriteThrough),
    //     MtrrMemoryRange::new(0x0000400000000000, 0x0000400000000000, MtrrMemoryCacheType::WriteThrough),
    //     MtrrMemoryRange::new(0x00004c09b0000000, 0x0000000010000000, MtrrMemoryCacheType::WriteBack),
    //     MtrrMemoryRange::new(0x0000c32800000000, 0x0000000008000000, MtrrMemoryCacheType::WriteProtected),
    //     MtrrMemoryRange::new(0x0000c00000000000, 0x0000004000000000, MtrrMemoryCacheType::WriteCombining),
    //     MtrrMemoryRange::new(0x0000e70000000000, 0x0000000000020000, MtrrMemoryCacheType::WriteCombining),
    //     MtrrMemoryRange::new(0x0000b13000000000, 0x0000000008000000, MtrrMemoryCacheType::WriteCombining),
    //     ];
    //   raw_mtrr_range_count = raw_mtrr_range.len() as u32;
    //     // TESTCODE end

    println!("--- Raw MTRR Range [{}]---", raw_mtrr_range_count);
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

    for index in 0..expected_memory_ranges_count {
        println!("--------------------------------------------------");
        println!("--------------------------------------------------");
        println!("{} calling mtrr_set_memory_attribute", index);

        // println!("Before: \n{}", mtrr_setting);
        status = mtrrlib.mtrr_set_memory_attribute(
            expected_memory_ranges[index].base_address,
            expected_memory_ranges[index].length,
            expected_memory_ranges[index].mem_type,
        );
        // println!("After: \n{}", mtrr_setting);

        if status.is_err() {
            return;
        }
    }

    let mtrr_setting = mtrrlib.mtrr_get_all_mtrrs();

    actual_memory_ranges_count = actual_memory_ranges.len();
    collect_test_result(
        system_parameter.default_cache_type,
        system_parameter.physical_address_bits as u32 - system_parameter.mk_tme_keyid_bits as u32,
        system_parameter.variable_mtrr_count,
        &mtrr_setting,
        &mut actual_memory_ranges,
        &mut actual_memory_ranges_count,
        &mut actual_variable_mtrr_usage,
    );

    println!("--- Raw MTRR Range [{}]---", raw_mtrr_range_count);
    dump_memory_ranges(&raw_mtrr_range, raw_mtrr_range_count as usize);
    println!("--- Actual Memory Ranges [{}] ---", actual_memory_ranges_count);
    dump_memory_ranges(&actual_memory_ranges, actual_memory_ranges_count);
    println!("--- Expected Memory Ranges [{}] ---", expected_memory_ranges_count);
    dump_memory_ranges(&expected_memory_ranges, expected_memory_ranges_count);
    verify_memory_ranges(
        &expected_memory_ranges[..],
        expected_memory_ranges_count,
        &actual_memory_ranges,
        actual_memory_ranges_count,
    );
    assert!(raw_mtrr_range_count >= actual_variable_mtrr_usage);

    returned_memory_ranges_count = returned_memory_ranges.len();
    status = mtrrlib.mtrr_get_memory_ranges(&mut returned_memory_ranges[..], Some(&mut returned_memory_ranges_count));
    assert!(status.is_ok());
    println!("--- Returned Memory Ranges [{}] ---", returned_memory_ranges_count);
    dump_memory_ranges(&returned_memory_ranges, returned_memory_ranges_count);
    verify_memory_ranges(
        &expected_memory_ranges,
        expected_memory_ranges_count,
        &returned_memory_ranges,
        returned_memory_ranges_count,
    );

    println!(
        "------------unit_test_mtrr_set_memory_attribute_and_get_memory_attributes_with_empty_mtrr_settings end------------"
    );
}

#[test]
fn unit_test_mtrr_lib_use_case() {
    // Initialize the hardware abstraction layer
    let system_parameter = MtrrLibSystemParameter::new(38, true, true, MtrrMemoryCacheType::Uncacheable, 12, 0);
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);

    // Create MTRR library
    let mut mtrrlib = create_mtrr_lib_with_mock_hal(hal);

    // Get the current MTRR settings
    let mut mtrr_settings = mtrrlib.mtrr_get_all_mtrrs();
    for index in 0..mtrr_settings.fixed.mtrr.len() {
        mtrr_settings.fixed.mtrr[index] = 0x0606060606060606;
    }
    mtrr_settings.mtrr_def_type_reg.set_mem_type(MtrrMemoryCacheType::WriteBack as u8);

    // Set the MTRR settings
    mtrrlib.mtrr_set_all_mtrrs(&mtrr_settings);

    const BASE_128KB: u64 = 0x00020000;
    const BASE_512KB: u64 = 0x00080000;
    const BASE_1MB: u64 = 0x00100000;
    const BASE_4GB: u64 = 0x0000000100000000;

    let status = mtrrlib.mtrr_set_memory_attribute(
        BASE_512KB + BASE_128KB,
        BASE_1MB - (BASE_512KB + BASE_128KB),
        MtrrMemoryCacheType::Uncacheable,
    );
    assert!(status.is_ok());

    let status = mtrrlib.mtrr_set_memory_attribute(0xB0000000, BASE_4GB - 0xB0000000, MtrrMemoryCacheType::Uncacheable);
    assert!(status.is_ok());

    // MTRR Settings:
    // =============
    // MTRR Default Type: 0x00000000000c06
    // Fixed MTRR[00]   : 0x606060606060606
    // Fixed MTRR[01]   : 0x606060606060606
    // Fixed MTRR[02]   : 0x00000000000000
    // Fixed MTRR[03]   : 0x00000000000000
    // Fixed MTRR[04]   : 0x00000000000000
    // Fixed MTRR[05]   : 0x00000000000000
    // Fixed MTRR[06]   : 0x00000000000000
    // Fixed MTRR[07]   : 0x00000000000000
    // Fixed MTRR[08]   : 0x00000000000000
    // Fixed MTRR[09]   : 0x00000000000000
    // Fixed MTRR[10]   : 0x00000000000000
    // Variable MTRR[00]: Base=0x000000c0000000 Mask=0x00003fc0000800
    // Variable MTRR[01]: Base=0x000000b0000000 Mask=0x00003ff0000800
    // Memory Ranges:
    // ====================================
    // WB:0x00000000000000-0x0000000009ffff
    // UC:0x000000000a0000-0x000000000fffff
    // WB:0x00000000100000-0x000000afffffff
    // UC:0x000000b0000000-0x000000ffffffff
    // WB:0x00000100000000-0x00003fffffffff
}
