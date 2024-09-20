use mtrr::{
    edk_error::{RETURN_BUFFER_TOO_SMALL, RETURN_SUCCESS},
    mtrr::{get_pcd_cpu_number_of_reserved_variable_mtrrs, mtrr_get_default_memory_type, mtrr_set_memory_attributes_in_mtrr_settings},
    structs::{
        MsrIa32MtrrDefType, MsrIa32MtrrPhysbaseRegister, MsrIa32MtrrPhysmaskRegister, MtrrMemoryCacheType,
        MtrrMemoryRange, MtrrSettings, MtrrVariableSetting, MSR_IA32_MTRR_FIX16K_80000, MSR_IA32_MTRR_FIX16K_A0000,
        MSR_IA32_MTRR_FIX4K_C0000, MSR_IA32_MTRR_FIX4K_C8000, MSR_IA32_MTRR_FIX4K_D0000, MSR_IA32_MTRR_FIX4K_D8000,
        MSR_IA32_MTRR_FIX4K_E0000, MSR_IA32_MTRR_FIX4K_E8000, MSR_IA32_MTRR_FIX4K_F0000, MSR_IA32_MTRR_FIX4K_F8000,
        MSR_IA32_MTRR_FIX64K_00000, MTRR_NUMBER_OF_FIXED_MTRR, MTRR_NUMBER_OF_LOCAL_MTRR_RANGES,
        MTRR_NUMBER_OF_VARIABLE_MTRR, SIZE_1MB,
    },
};
use rand::random;
use rand::Rng;
use support::{generate_random_memory_type_combination, generate_valid_and_configurable_mtrr_pairs, get_effective_memory_ranges};
use std::ptr;
mod support;

pub const SCRATCH_BUFFER_SIZE: usize = 16 * 1024; // 16KB equivalent

#[repr(C)]
pub struct MtrrLibSystemParameter {
    physical_address_bits: u8,
    mtrr_supported: bool,
    fixed_mtrr_supported: bool,
    default_cache_type: MtrrMemoryCacheType, // Assuming this is an enum or type alias
    variable_mtrr_count: u32,
    mk_tme_keyid_bits: u8,
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

static M_FIXED_MTRRS_INDEX: [u32; 11] = [
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

/**
  Compare the actual memory ranges against expected memory ranges and return PASS when they match.

  @param ExpectedMemoryRanges     Expected memory ranges.
  @param ExpectedMemoryRangeCount Count of expected memory ranges.
  @param ActualRanges             Actual memory ranges.
  @param ActualRangeCount         Count of actual memory ranges.

  @retval UNIT_TEST_PASSED  Test passed.
  @retval others            Test failed.
**/
fn verify_memory_ranges(expected_memory_ranges: &[MtrrMemoryRange], actual_ranges: &[MtrrMemoryRange]) {
    assert_eq!(expected_memory_ranges.len(), actual_ranges.len());

    for (expected, actual) in expected_memory_ranges.iter().zip(actual_ranges.iter()) {
        assert_eq!(expected.base_address, actual.base_address);
        assert_eq!(expected.length, actual.length);
        assert_eq!(expected.mem_type, actual.mem_type);
    }
}

/**
  Dump the memory ranges.

  @param Ranges       Memory ranges to dump.
  @param RangeCount   Count of memory ranges.
**/
pub fn dump_memory_ranges(ranges: &[MtrrMemoryRange], range_count: usize) {
    for index in 0..range_count {
        println!(
            "\t{{ 0x{:016x}, 0x{:016x}, {:?} }},",
            ranges[index].base_address, ranges[index].length, ranges[index].mem_type
        );
    }
}


/**
  Unit test of MtrrLib service MtrrGetMemoryAttributesInMtrrSettings() and
  MtrrSetMemoryAttributesInMtrrSettings()

  @param[in]  Context    Ignored

  @retval  UNIT_TEST_PASSED             The Unit test has completed and the test
                                        case was successful.
  @retval  UNIT_TEST_ERROR_TEST_FAILED  A test case assertion has failed.

**/
pub fn unit_test_mtrr_set_and_get_memory_attributes_in_mtrr_settings(
    context: &MtrrLibSystemParameter,
) {
    let system_parameter = context;
    let mut uc_count = 0;
    let mut wt_count = 0;
    let mut wb_count = 0;
    let mut wp_count = 0;
    let mut wc_count = 0;

    let mut mtrr_index;
    let mut scratch;
    let mut scratch_size;
    let mut local_mtrrs = MtrrSettings::default();

    let mut raw_mtrr_range = vec![MtrrMemoryRange::default(); MTRR_NUMBER_OF_VARIABLE_MTRR];
    let mut expected_memory_ranges = vec![MtrrMemoryRange::default(); MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let mut expected_variable_mtrr_usage;
    let mut expected_memory_ranges_count;

    let mut actual_memory_ranges = vec![MtrrMemoryRange::default(); MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let mut actual_variable_mtrr_usage;
    let mut actual_memory_ranges_count;

    let mut returned_memory_ranges = vec![MtrrMemoryRange::default(); MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let mut returned_memory_ranges_count;

    let mut mtrrs = vec![&mut local_mtrrs, &mut MtrrSettings::default()];

    generate_random_memory_type_combination(
        system_parameter.variable_mtrr_count - get_pcd_cpu_number_of_reserved_variable_mtrrs(),
        &mut uc_count,
        &mut wt_count,
        &mut wb_count,
        &mut wp_count,
        &mut wc_count,
    );
    generate_valid_and_configurable_mtrr_pairs(
        (system_parameter.physical_address_bits - system_parameter.mk_tme_keyid_bits) as u32,
        &mut raw_mtrr_range,
        uc_count,
        wt_count,
        wb_count,
        wp_count,
        wc_count,
    );

    expected_variable_mtrr_usage = uc_count + wt_count + wb_count + wp_count + wc_count;
    expected_memory_ranges_count = expected_memory_ranges.len();
    get_effective_memory_ranges(
        system_parameter.default_cache_type,
        (system_parameter.physical_address_bits - system_parameter.mk_tme_keyid_bits) as u32,
        &raw_mtrr_range,
        expected_variable_mtrr_usage as usize,
        &mut expected_memory_ranges,
        &mut expected_memory_ranges_count,
    );

    println!(
        "Total MTRR [{}]: UC={}, WT={}, WB={}, WP={}, WC={}",
        expected_variable_mtrr_usage,
        uc_count,
        wt_count,
        wb_count,
        wp_count,
        wc_count
    );
    println!("--- Expected Memory Ranges [{}] ---", expected_memory_ranges_count);
    dump_memory_ranges(&expected_memory_ranges, expected_memory_ranges_count);

    // Default cache type is always an INPUT
    local_mtrrs.mtrr_def_type = mtrr_get_default_memory_type() as u64;
    scratch_size = SCRATCH_BUFFER_SIZE;
    mtrrs[0] = &mut local_mtrrs;
    mtrrs[1] = &mut MtrrSettings::default();

    for mtrr_index in 0..mtrrs.len() {
        scratch = vec![0u8; scratch_size];
        let mut status = mtrr_set_memory_attributes_in_mtrr_settings(
            Some(mtrrs[mtrr_index]),
            &mut scratch,
            &mut scratch_size,
            &expected_memory_ranges,
            expected_memory_ranges_count,
        );
        if status == RETURN_BUFFER_TOO_SMALL {
            scratch.resize(scratch_size, 0);
            println!("Not enough scratch space");
            status = mtrr_set_memory_attributes_in_mtrr_settings(
                Some(mtrrs[mtrr_index]),
                &mut scratch,
                &mut scratch_size,
                &expected_memory_ranges,
                expected_memory_ranges_count,
            );
        }

        assert_eq!(status, RETURN_SUCCESS);

        if mtrrs[mtrr_index] == MtrrSettings::default() {
            local_mtrrs = MtrrSettings::default();
            mtrr_get_all_mtrrs(&mut local_mtrrs);
        }

        actual_memory_ranges_count = actual_memory_ranges.len();
        collect_test_result(
            system_parameter.default_cache_type,
            system_parameter.physical_address_bits - system_parameter.mk_tme_keyid_bits,
            system_parameter.variable_mtrr_count,
            &local_mtrrs,
            &mut actual_memory_ranges,
            &mut actual_memory_ranges_count,
            &mut actual_variable_mtrr_usage,
        );

        println!("--- Actual Memory Ranges [{}] ---", actual_memory_ranges_count);
        dump_memory_ranges(&actual_memory_ranges, actual_memory_ranges_count);
        verify_memory_ranges(
            &expected_memory_ranges,
            expected_memory_ranges_count,
            &actual_memory_ranges,
            actual_memory_ranges_count,
        );
        ut_assert_true!(expected_variable_mtrr_usage >= actual_variable_mtrr_usage);

        returned_memory_ranges_count = returned_memory_ranges.len();
        status = mtrr_get_memory_attributes_in_mtrr_settings(
            mtrrs[mtrr_index],
            &mut returned_memory_ranges,
            &mut returned_memory_ranges_count,
        );
        assert_eq!(status, RETURN_SUCCESS);
        println!("--- Returned Memory Ranges [{}] ---", returned_memory_ranges_count);
        dump_memory_ranges(&returned_memory_ranges, returned_memory_ranges_count);
        verify_memory_ranges(
            &expected_memory_ranges,
            expected_memory_ranges_count,
            &returned_memory_ranges,
            returned_memory_ranges_count,
        );

        local_mtrrs = MtrrSettings::default();
    }

}