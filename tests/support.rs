use mtrr::structs::{MtrrSettings, CPUID_EXTENDED_FUNCTION, CPUID_SIGNATURE, CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS, CPUID_VERSION_INFO, CPUID_VIR_PHY_ADDRESS_SIZE};
use mtrr::structs::{
    MsrIa32MtrrPhysbaseRegister, MsrIa32MtrrPhysmaskRegister, MtrrMemoryCacheType, MtrrMemoryRange,
    MtrrVariableSetting, SIZE_1MB,
};

use rand::random;
use rand::Rng;
use std::cmp::Ordering;

use crate::MtrrLibSystemParameter;



pub fn unit_test_mtrr_lib_asm_cpuid_ex(
    index: u32,
    sub_index: u32,
    eax: Option<&mut u32>,
    ebx: Option<&mut u32>,
    ecx: Option<&mut u32>,
    edx: Option<&mut u32>,
) -> u32 {
    match index {
        CPUID_SIGNATURE => {
            if let Some(eax) = eax {
                *eax = CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS;
            }
            index
        }
        CPUID_VERSION_INFO => {
            if let Some(edx) = edx {
                *edx = m_cpuid_version_info_edx.uint32;
            }
            index
        }
        CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS => {
            if let Some(ecx) = ecx {
                *ecx = m_cpuid_extended_feature_flags_ecx.uint32;
            }
            index
        }
        CPUID_EXTENDED_FUNCTION => {
            if let Some(eax) = eax {
                *eax = CPUID_VIR_PHY_ADDRESS_SIZE;
            }
            index
        }
        CPUID_VIR_PHY_ADDRESS_SIZE => {
            if let Some(eax) = eax {
                *eax = m_cpuid_vir_phy_address_size_eax.uint32;
            }
            index
        }
        _ => {
            panic!("Should never fall through to here");
        }
    }
}

// pub fn initialize_mtrr_regs(system_parameter: &MtrrLibSystemParameter) -> UnitTestStatus {
//     for value in m_fixed_mtrrs_value.iter_mut() {
//         *value = system_parameter.default_cache_type;
//     }

//     for index in 0..m_variable_mtrrs_phys_base.len() {
//         m_variable_mtrrs_phys_base[index].uint64 = 0;
//         m_variable_mtrrs_phys_mask[index].uint64 = 0;
//     }

//     m_def_type_msr.bits.e = 1;
//     m_def_type_msr.bits.fe = 0;
//     m_def_type_msr.bits.type_ = system_parameter.default_cache_type;
//     m_def_type_msr.bits.reserved1 = 0;
//     m_def_type_msr.bits.reserved2 = 0;
//     m_def_type_msr.bits.reserved3 = 0;

//     m_mtrr_cap_msr.bits.smrr = 0;
//     m_mtrr_cap_msr.bits.wc = 0;
//     m_mtrr_cap_msr.bits.vcnt = system_parameter.variable_mtrr_count;
//     m_mtrr_cap_msr.bits.fix = system_parameter.fixed_mtrr_supported;
//     m_mtrr_cap_msr.bits.reserved1 = 0;
//     m_mtrr_cap_msr.bits.reserved2 = 0;
//     m_mtrr_cap_msr.bits.reserved3 = 0;

//     m_cpuid_version_info_edx.bits.mtrr = system_parameter.mtrr_supported;
//     m_cpuid_vir_phy_address_size_eax.bits.physical_address_bits = system_parameter.physical_address_bits;

//     // Hook BaseLib functions used by MtrrLib that require some emulation.
//     g_unit_test_host_base_lib.x86.asm_cpuid = unit_test_mtrr_lib_asm_cpuid;
//     g_unit_test_host_base_lib.x86.asm_cpuid_ex = unit_test_mtrr_lib_asm_cpuid_ex;

//     g_unit_test_host_base_lib.x86.asm_read_msr64 = unit_test_mtrr_lib_asm_read_msr64;
//     g_unit_test_host_base_lib.x86.asm_write_msr64 = unit_test_mtrr_lib_asm_write_msr64;

//     if system_parameter.mk_tme_keyid_bits != 0 {
//         m_cpuid_extended_feature_flags_ecx.bits.tme_en = 1;
//         m_tme_activate_msr.bits.tme_enable = 1;
//         m_tme_activate_msr.bits.mk_tme_keyid_bits = system_parameter.mk_tme_keyid_bits;
//     } else {
//         m_cpuid_extended_feature_flags_ecx.bits.tme_en = 0;
//         m_tme_activate_msr.bits.tme_enable = 0;
//         m_tme_activate_msr.bits.mk_tme_keyid_bits = 0;
//     }

//     UnitTestStatus::Passed
// }

// /**
//   Initialize the MTRR registers.

//   @param Context System parameter that controls the MTRR registers initialization.
// **/
// pub fn initialize_system(context: &MtrrLibSystemParameter) -> UnitTestStatus {
//     initialize_mtrr_regs(context)
// }

/**
  Collect the test result.

  @param DefaultType          Default memory type.
  @param PhysicalAddressBits  Physical address bits.
  @param VariableMtrrCount    Count of variable MTRRs.
  @param Mtrrs                MTRR settings to collect from.
  @param Ranges               Return the memory ranges.
  @param RangeCount           Return the count of memory ranges.
  @param MtrrCount            Return the count of variable MTRRs being used.
**/
pub fn collect_test_result(
    default_type: MtrrMemoryCacheType,
    physical_address_bits: u32,
    variable_mtrr_count: u32,
    mtrrs: &MtrrSettings,
    ranges: &mut Vec<MtrrMemoryRange>,
    range_count: &mut usize,
    mtrr_count: &mut u32,
) {
    let mtrr_valid_bits_mask = (1u64 << physical_address_bits) - 1;
    let mtrr_valid_address_mask = mtrr_valid_bits_mask & !0xFFFu64;
    let mut raw_memory_ranges = vec![MtrrMemoryRange::default(); mtrrs.variables.mtrr.len()];

    assert!(variable_mtrr_count <= mtrrs.variables.mtrr.len() as u32);

    *mtrr_count = 0;
    for index in 0..variable_mtrr_count as usize {
        if mtrrs.variables.mtrr[index].mask.bits.v == 1 {
            raw_memory_ranges[*mtrr_count as usize].base_address = mtrrs.variables.mtrr[index].base & mtrr_valid_address_mask;
            raw_memory_ranges[*mtrr_count as usize].mem_type = mtrrs.variables.mtrr[index].base.bits.type_;
            raw_memory_ranges[*mtrr_count as usize].length = (!mtrrs.variables.mtrr[index].mask & mtrr_valid_address_mask & mtrr_valid_bits_mask) + 1;
            *mtrr_count += 1;
        }
    }

    get_effective_memory_ranges(
        default_type,
        physical_address_bits,
        &raw_memory_ranges,
        *mtrr_count as usize,
        ranges,
        range_count,
    );
}

/**
  Return a 32bit random number.

  @param Start  Start of the random number range.
  @param Limit  Limit of the random number range.
  @return 32bit random number
**/
pub fn random32(start: u32, limit: u32) -> u32 {
    let mut rng = rand::thread_rng();
    rng.gen_range(start..limit)
}

/**
  Return a 64bit random number.

  @param Start  Start of the random number range.
  @param Limit  Limit of the random number range.
  @return 64bit random number
**/
pub fn random64(start: u64, limit: u64) -> u64 {
    let mut rng = rand::thread_rng();
    rng.gen_range(start..limit)
}


/**
  Generate random count of MTRRs for each cache type.

  @param TotalCount Total MTRR count.
  @param UcCount    Return count of Uncacheable type.
  @param WtCount    Return count of Write Through type.
  @param WbCount    Return count of Write Back type.
  @param WpCount    Return count of Write Protected type.
  @param WcCount    Return count of Write Combining type.
**/
pub fn generate_random_memory_type_combination(
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
}

/**
  Generate random MTRR BASE/MASK for a specified type.

  @param PhysicalAddressBits Physical address bits.
  @param CacheType           Cache type.
  @param MtrrPair            Return the random MTRR.
  @param MtrrMemoryRange     Return the random memory range.
**/
pub fn generate_random_mtrr_pair(
    physical_address_bits: u32,
    cache_type: MtrrMemoryCacheType,
    mtrr_pair: Option<&mut MtrrVariableSetting>,
    mtrr_memory_range: Option<&mut MtrrMemoryRange>,
) {
    let max_physical_address = 1u64 << physical_address_bits;
    let mut rng = rand::thread_rng();
    let mut size_shift;
    let mut range_size;
    let mut base_shift;
    let mut random_boundary;
    let mut range_base;
    let phys_base_phy_mask_valid_bits_mask;

    loop {
        size_shift = rng.gen_range(12..physical_address_bits);
        range_size = 1u64 << size_shift;

        base_shift = rng.gen_range(size_shift..physical_address_bits);
        random_boundary = rng.gen_range(0..(1u64 << (physical_address_bits - base_shift)));
        range_base = random_boundary << base_shift;

        if range_base >= SIZE_1MB as u64 && range_base <= max_physical_address - 1 {
            break;
        }
    }

    phys_base_phy_mask_valid_bits_mask = (max_physical_address - 1) & 0xfffffffffffff000u64;

    let mut phys_base;
    phys_base = MsrIa32MtrrPhysbaseRegister::from_bits(range_base & phys_base_phy_mask_valid_bits_mask);
    phys_base.set_mem_type(cache_type as u8);

    let mut phys_mask;
    phys_mask = MsrIa32MtrrPhysmaskRegister::from_bits((!range_size + 1) & phys_base_phy_mask_valid_bits_mask);
    phys_mask.set_v(true);

    if let Some(mtrr_pair) = mtrr_pair {
        mtrr_pair.base = phys_base.into();
        mtrr_pair.mask = phys_mask.into();
    }

    if let Some(mtrr_memory_range) = mtrr_memory_range {
        mtrr_memory_range.base_address = range_base;
        mtrr_memory_range.length = range_size;
        mtrr_memory_range.mem_type = cache_type;
    }
}

/**
  Check whether the Range overlaps with any one in Ranges.

  @param Range  The memory range to check.
  @param Ranges The memory ranges.
  @param Count  Count of memory ranges.

  @return TRUE when overlap exists.
**/
pub fn ranges_overlap(range: &MtrrMemoryRange, ranges: &[MtrrMemoryRange], count: usize) -> bool {
    let mut count = count;
    // Two ranges overlap when:
    // 1. range#2.base is in the middle of range#1
    // 2. range#1.base is in the middle of range#2
    while count != 0 {
        count -= 1;

        if (range.base_address <= ranges[count].base_address
            && ranges[count].base_address < range.base_address + range.length)
            || (ranges[count].base_address <= range.base_address
                && range.base_address < ranges[count].base_address + ranges[count].length)
        {
            return true;
        }
    }

    false
}

/**
  Generate random MTRRs.

  @param PhysicalAddressBits  Physical address bits.
  @param RawMemoryRanges      Return the randomly generated MTRRs.
  @param UcCount              Count of Uncacheable MTRRs.
  @param WtCount              Count of Write Through MTRRs.
  @param WbCount              Count of Write Back MTRRs.
  @param WpCount              Count of Write Protected MTRRs.
  @param WcCount              Count of Write Combine MTRRs.
**/
pub fn generate_valid_and_configurable_mtrr_pairs(
    physical_address_bits: u32,
    raw_memory_ranges: &mut [MtrrMemoryRange],
    uc_count: u32,
    wt_count: u32,
    wb_count: u32,
    wp_count: u32,
    wc_count: u32,
) {
    let mut index = 0;

    // 1. Generate UC, WT, WB in order.
    for index in 0..uc_count {
        generate_random_mtrr_pair(
            physical_address_bits,
            MtrrMemoryCacheType::Uncacheable,
            None,
            Some(&mut raw_memory_ranges[index as usize]),
        );
    }

    for index in uc_count..(uc_count + wt_count) {
        generate_random_mtrr_pair(
            physical_address_bits,
            MtrrMemoryCacheType::WriteThrough,
            None,
            Some(&mut raw_memory_ranges[index as usize]),
        );
    }

    for index in (uc_count + wt_count)..(uc_count + wt_count + wb_count) {
        generate_random_mtrr_pair(
            physical_address_bits,
            MtrrMemoryCacheType::WriteBack,
            None,
            Some(&mut raw_memory_ranges[index as usize]),
        );
    }

    // 2. Generate WP MTRR and DO NOT overlap with WT, WB.
    for index in (uc_count + wt_count + wb_count)..(uc_count + wt_count + wb_count + wp_count) {
        generate_random_mtrr_pair(
            physical_address_bits,
            MtrrMemoryCacheType::WriteProtected,
            None,
            Some(&mut raw_memory_ranges[index as usize]),
        );
        while ranges_overlap(
            &raw_memory_ranges[index as usize],
            &raw_memory_ranges[uc_count as usize..],
            (wt_count + wb_count) as usize,
        ) {
            generate_random_mtrr_pair(
                physical_address_bits,
                MtrrMemoryCacheType::WriteProtected,
                None,
                Some(&mut raw_memory_ranges[index as usize]),
            );
        }
    }

    // 3. Generate WC MTRR and DO NOT overlap with WT, WB, WP.
    for index in (uc_count + wt_count + wb_count + wp_count)..(uc_count + wt_count + wb_count + wp_count + wc_count) {
        generate_random_mtrr_pair(
            physical_address_bits,
            MtrrMemoryCacheType::WriteCombining,
            None,
            Some(&mut raw_memory_ranges[index as usize]),
        );
        while ranges_overlap(
            &raw_memory_ranges[index as usize],
            &raw_memory_ranges[uc_count as usize..],
            (wt_count + wb_count + wp_count) as usize,
        ) {
            generate_random_mtrr_pair(
                physical_address_bits,
                MtrrMemoryCacheType::WriteCombining,
                None,
                Some(&mut raw_memory_ranges[index as usize]),
            );
        }
    }
}

/**
  Return a random memory cache type.
**/
pub fn generate_random_cache_type() -> MtrrMemoryCacheType {
    let cache_types = [
        MtrrMemoryCacheType::Uncacheable,
        MtrrMemoryCacheType::WriteCombining,
        MtrrMemoryCacheType::WriteThrough,
        MtrrMemoryCacheType::WriteProtected,
        MtrrMemoryCacheType::WriteBack,
    ];
    let mut rng = rand::thread_rng();
    cache_types[rng.gen_range(0..cache_types.len())]
}

/**
  Compare function used by qsort().
**/

/**
  Compare function used by qsort().

  @param Left   Left operand to compare.
  @param Right  Right operand to compare.

  @retval 0  Left == Right
  @retval -1 Left < Right
  @retval 1  Left > Right
**/
pub fn compare_func_uint64(left: &u64, right: &u64) -> i32 {
    let delta = *left as i64 - *right as i64;
    if delta > 0 {
        1
    } else if delta == 0 {
        0
    } else {
        -1
    }
}

/**
  Determin the memory cache type for the Range.

  @param DefaultType Default cache type.
  @param Range       The memory range to determin the cache type.
  @param Ranges      The entire memory ranges.
  @param RangeCount  Count of the entire memory ranges.
**/
pub fn determine_memory_cache_type(
    default_type: MtrrMemoryCacheType,
    range: &mut MtrrMemoryRange,
    ranges: &[MtrrMemoryRange],
    range_count: u32,
) {
    range.mem_type = MtrrMemoryCacheType::Invalid;
    for index in 0..range_count as usize {
        if ranges_overlap(range, &ranges[index..index + 1], 1) {
            if (ranges[index as usize].mem_type as u8) < (range.mem_type as u8) {
                range.mem_type = ranges[index as usize].mem_type;
            }
        }
    }

    if range.mem_type == MtrrMemoryCacheType::Invalid {
        range.mem_type = default_type;
    }
}

/**
  Get the index of the element that does NOT equals to Array[Index].

  @param Index   Current element.
  @param Array   Array to scan.
  @param Count   Count of the array.

  @return Next element that doesn't equal to current one.
**/
pub fn get_next_different_element_in_sorted_array(index: u32, array: &[u64], count: u32) -> u32 {
    let current_element = array[index as usize];
    let mut index = index;
    while current_element == array[index as usize] && index < count {
        index += 1;
    }
    index
}

/**
  Remove the duplicates from the array.

  @param Array  The array to operate on.
  @param Count  Count of the array.
**/
pub fn remove_duplicates_in_sorted_array(array: &mut [u64], count: &mut u32) {
    let mut index = 0;
    let mut new_count = 0;
    while index < *count {
        array[new_count as usize] = array[index as usize];
        new_count += 1;
        index = get_next_different_element_in_sorted_array(index, array, *count);
    }
    *count = new_count;
}

/**
  Return TRUE when Address is in the Range.

  @param Address The address to check.
  @param Range   The range to check.
  @return TRUE when Address is in the Range.
**/
pub fn address_in_range(address: u64, range: &MtrrMemoryRange) -> bool {
    address >= range.base_address && address <= range.base_address + range.length - 1
}

/**
  Get the overlap bit flag.

  @param RawMemoryRanges     Raw memory ranges.
  @param RawMemoryRangeCount Count of raw memory ranges.
  @param Address             The address to check.
**/
pub fn get_overlap_bit_flag(raw_memory_ranges: &[MtrrMemoryRange], raw_memory_range_count: u32, address: u64) -> u64 {
    let mut overlap_bit_flag = 0;
    for index in 0..raw_memory_range_count {
        if address_in_range(address, &raw_memory_ranges[index as usize]) {
            overlap_bit_flag |= 1u64 << index;
        }
    }
    overlap_bit_flag
}

/**
  Return the relationship between flags.

  @param Flag1 Flag 1
  @param Flag2 Flag 2

  @retval 0   Flag1 == Flag2
  @retval 1   Flag1 is a subset of Flag2
  @retval 2   Flag2 is a subset of Flag1
  @retval 3   No subset relations between Flag1 and Flag2.
**/
pub fn check_overlap_bit_flags_relation(flag1: u64, flag2: u64) -> u32 {
    if flag1 == flag2 {
        0
    } else if (flag1 | flag2) == flag2 {
        1
    } else if (flag1 | flag2) == flag1 {
        2
    } else {
        3
    }
}

/**
  Return TRUE when the Endpoint is in any of the Ranges.

  @param Endpoint    The endpoint to check.
  @param Ranges      The memory ranges.
  @param RangeCount  Count of memory ranges.

  @retval TRUE  Endpoint is in one of the range.
  @retval FALSE Endpoint is not in any of the ranges.
**/
pub fn is_endpoint_in_ranges(endpoint: u64, ranges: &[MtrrMemoryRange], range_count: usize) -> bool {
    for index in 0..range_count {
        if address_in_range(endpoint, &ranges[index]) {
            return true;
        }
    }
    false
}

/**
  Compact adjacent ranges of the same type.

  @param DefaultType                    Default memory type.
  @param PhysicalAddressBits            Physical address bits.
  @param EffectiveMtrrMemoryRanges      Memory ranges to compact.
  @param EffectiveMtrrMemoryRangesCount Return the new count of memory ranges.
**/
pub fn compact_and_extend_effective_mtrr_memory_ranges(
    default_type: MtrrMemoryCacheType,
    physical_address_bits: u32,
    effective_mtrr_memory_ranges: &mut Vec<MtrrMemoryRange>,
    effective_mtrr_memory_ranges_count: &mut usize,
) {
    let max_address = (1u64 << physical_address_bits) - 1;
    let new_ranges_count_at_most = *effective_mtrr_memory_ranges_count + 2;
    let mut new_ranges = vec![MtrrMemoryRange::default(); new_ranges_count_at_most];
    let old_ranges = effective_mtrr_memory_ranges.clone();
    let mut new_ranges_count_actual = 0;

    if old_ranges[0].base_address > 0 {
        new_ranges[new_ranges_count_actual].base_address = 0;
        new_ranges[new_ranges_count_actual].length = old_ranges[0].base_address;
        new_ranges[new_ranges_count_actual].mem_type = default_type;
        new_ranges_count_actual += 1;
    }

    let mut old_ranges_index = 0;
    while old_ranges_index < *effective_mtrr_memory_ranges_count {
        let current_range_type_in_old_ranges = old_ranges[old_ranges_index].mem_type;
        let mut current_range_in_new_ranges: Option<&mut MtrrMemoryRange> = None;

        if new_ranges_count_actual > 0 {
            current_range_in_new_ranges = Some(&mut new_ranges[new_ranges_count_actual - 1]);
        }

        if let Some(current_range) = current_range_in_new_ranges {
            if current_range.mem_type == current_range_type_in_old_ranges {
                current_range.length += old_ranges[old_ranges_index].length;
            } else {
                new_ranges[new_ranges_count_actual].base_address = old_ranges[old_ranges_index].base_address;
                new_ranges[new_ranges_count_actual].length = old_ranges[old_ranges_index].length;
                new_ranges[new_ranges_count_actual].mem_type = current_range_type_in_old_ranges;

                while old_ranges_index + 1 < *effective_mtrr_memory_ranges_count
                    && old_ranges[old_ranges_index + 1].mem_type == current_range_type_in_old_ranges
                {
                    old_ranges_index += 1;
                    new_ranges[new_ranges_count_actual].length += old_ranges[old_ranges_index].length;
                }

                new_ranges_count_actual += 1;
            }
        } else {
            new_ranges[new_ranges_count_actual].base_address = old_ranges[old_ranges_index].base_address;
            new_ranges[new_ranges_count_actual].length = old_ranges[old_ranges_index].length;
            new_ranges[new_ranges_count_actual].mem_type = current_range_type_in_old_ranges;

            while old_ranges_index + 1 < *effective_mtrr_memory_ranges_count
                && old_ranges[old_ranges_index + 1].mem_type == current_range_type_in_old_ranges
            {
                old_ranges_index += 1;
                new_ranges[new_ranges_count_actual].length += old_ranges[old_ranges_index].length;
            }

            new_ranges_count_actual += 1;
        }

        old_ranges_index += 1;
    }

    let old_last_range = old_ranges[*effective_mtrr_memory_ranges_count - 1];
    let current_range_in_new_ranges = &mut new_ranges[new_ranges_count_actual - 1];

    if old_last_range.base_address + old_last_range.length - 1 < max_address {
        if current_range_in_new_ranges.mem_type == default_type {
            current_range_in_new_ranges.length = max_address - current_range_in_new_ranges.base_address + 1;
        } else {
            new_ranges[new_ranges_count_actual].base_address = old_last_range.base_address + old_last_range.length;
            new_ranges[new_ranges_count_actual].length = max_address - new_ranges[new_ranges_count_actual].base_address + 1;
            new_ranges[new_ranges_count_actual].mem_type = default_type;
            new_ranges_count_actual += 1;
        }
    }

    *effective_mtrr_memory_ranges = new_ranges;
    *effective_mtrr_memory_ranges_count = new_ranges_count_actual;
}

/**
  Collect all the endpoints in the raw memory ranges.

  @param Endpoints           Return the collected endpoints.
  @param EndPointCount       Return the count of endpoints.
  @param RawMemoryRanges     Raw memory ranges.
  @param RawMemoryRangeCount Count of raw memory ranges.
**/
pub fn collect_endpoints(
    endpoints: &mut Vec<u64>,
    raw_memory_ranges: &[MtrrMemoryRange],
    raw_memory_range_count: usize,
) {
    assert_eq!(raw_memory_range_count << 1, endpoints.len());

    for (index, raw_range_index) in (0..endpoints.len()).step_by(2).enumerate() {
        endpoints[index] = raw_memory_ranges[raw_range_index].base_address;
        endpoints[index + 1] = raw_memory_ranges[raw_range_index].base_address + raw_memory_ranges[raw_range_index].length - 1;
    }

    endpoints.sort_unstable();
    endpoints.dedup();
}

/**
  Convert the MTRR BASE/MASK array to memory ranges.

  @param DefaultType          Default memory type.
  @param PhysicalAddressBits  Physical address bits.
  @param RawMemoryRanges      Raw memory ranges.
  @param RawMemoryRangeCount  Count of raw memory ranges.
  @param MemoryRanges         Memory ranges.
  @param MemoryRangeCount     Count of memory ranges.
**/
pub fn get_effective_memory_ranges(
    default_type: MtrrMemoryCacheType,
    physical_address_bits: u32,
    raw_memory_ranges: &[MtrrMemoryRange],
    raw_memory_range_count: usize,
    memory_ranges: &mut Vec<MtrrMemoryRange>,
    memory_range_count: &mut usize,
) {
    if raw_memory_range_count == 0 {
        memory_ranges[0].base_address = 0;
        memory_ranges[0].length = 1u64 << physical_address_bits;
        memory_ranges[0].mem_type = default_type;
        *memory_range_count = 1;
        return;
    }

    let all_endpoints_count = raw_memory_range_count << 1;
    let mut all_endpoints_inclusive = vec![0u64; all_endpoints_count];
    let all_range_pieces_count_max = raw_memory_range_count * 3 + 1;
    let mut all_range_pieces = vec![MtrrMemoryRange::default(); all_range_pieces_count_max];

    collect_endpoints(&mut all_endpoints_inclusive, raw_memory_ranges, raw_memory_range_count);

    let mut all_range_pieces_count_actual = 0;
    for index in 0..all_endpoints_count - 1 {
        let overlap_bit_flag1 = get_overlap_bit_flag(raw_memory_ranges, raw_memory_range_count as u32, all_endpoints_inclusive[index]);
        let overlap_bit_flag2 = get_overlap_bit_flag(raw_memory_ranges, raw_memory_range_count as u32, all_endpoints_inclusive[index + 1]);
        let overlap_flag_relation = check_overlap_bit_flags_relation(overlap_bit_flag1, overlap_bit_flag2);

        match overlap_flag_relation {
            0 => {
                all_range_pieces[all_range_pieces_count_actual].base_address = all_endpoints_inclusive[index];
                all_range_pieces[all_range_pieces_count_actual].length = all_endpoints_inclusive[index + 1] - all_endpoints_inclusive[index] + 1;
                all_range_pieces_count_actual += 1;
            }
            1 => {
                all_range_pieces[all_range_pieces_count_actual].base_address = all_endpoints_inclusive[index];
                all_range_pieces[all_range_pieces_count_actual].length = (all_endpoints_inclusive[index + 1] - 1) - all_endpoints_inclusive[index] + 1;
                all_range_pieces_count_actual += 1;
            }
            2 => {
                all_range_pieces[all_range_pieces_count_actual].base_address = all_endpoints_inclusive[index] + 1;
                all_range_pieces[all_range_pieces_count_actual].length = all_endpoints_inclusive[index + 1] - (all_endpoints_inclusive[index] + 1) + 1;
                all_range_pieces_count_actual += 1;

                if !is_endpoint_in_ranges(all_endpoints_inclusive[index], &all_range_pieces, all_range_pieces_count_actual) {
                    all_range_pieces[all_range_pieces_count_actual].base_address = all_endpoints_inclusive[index];
                    all_range_pieces[all_range_pieces_count_actual].length = 1;
                    all_range_pieces_count_actual += 1;
                }
            }
            3 => {
                all_range_pieces[all_range_pieces_count_actual].base_address = all_endpoints_inclusive[index] + 1;
                all_range_pieces[all_range_pieces_count_actual].length = (all_endpoints_inclusive[index + 1] - 1) - (all_endpoints_inclusive[index] + 1) + 1;
                if all_range_pieces[all_range_pieces_count_actual].length == 0 {
                    break;
                }
                all_range_pieces_count_actual += 1;

                if !is_endpoint_in_ranges(all_endpoints_inclusive[index], &all_range_pieces, all_range_pieces_count_actual) {
                    all_range_pieces[all_range_pieces_count_actual].base_address = all_endpoints_inclusive[index];
                    all_range_pieces[all_range_pieces_count_actual].length = 1;
                    all_range_pieces_count_actual += 1;
                }
            }
            _ => panic!("Unexpected overlap flag relation"),
        }
    }

    for index in 0..all_range_pieces_count_actual {
        determine_memory_cache_type(default_type, &mut all_range_pieces[index], raw_memory_ranges, raw_memory_range_count as u32);
    }

    compact_and_extend_effective_mtrr_memory_ranges(default_type, physical_address_bits, &mut all_range_pieces, &mut all_range_pieces_count_actual);
    assert!(*memory_range_count >= all_range_pieces_count_actual);
    memory_ranges.clear();
    memory_ranges.extend_from_slice(&all_range_pieces[..all_range_pieces_count_actual]);
    *memory_range_count = all_range_pieces_count_actual;
}
