use crate::structs::{
    MsrIa32MtrrPhysbaseRegister, MsrIa32MtrrPhysmaskRegister, MtrrMemoryCacheType, MtrrMemoryRange, MtrrSettings,
    MtrrVariableSetting, MTRR_NUMBER_OF_FIXED_MTRR, MTRR_NUMBER_OF_VARIABLE_MTRR, SIZE_1MB,
};

use rand::Rng;

//
//  Collect the test result.
//
//  @param DefaultType          Default memory type.
//  @param PhysicalAddressBits  Physical address bits.
//  @param VariableMtrrCount    Count of variable MTRRs.
//  @param Mtrrs                MTRR settings to collect from.
//  @param Ranges               Return the memory ranges.
//  @param RangeCount           Return the count of memory ranges.
//  @param MtrrCount            Return the count of variable MTRRs being used.
//
pub fn collect_test_result(
    default_type: MtrrMemoryCacheType,
    physical_address_bits: u32,
    variable_mtrr_count: u32,
    mtrrs: &MtrrSettings,
    ranges: &mut [MtrrMemoryRange],
    range_count: &mut usize,
    mtrr_count: &mut u32,
) {
    let mut raw_memory_ranges = [MtrrMemoryRange::default(); MTRR_NUMBER_OF_VARIABLE_MTRR];
    let mtrr_valid_bits_mask = (1u64 << physical_address_bits) - 1;
    let mtrr_valid_address_mask = mtrr_valid_bits_mask & !0xFFFu64;

    assert!(variable_mtrr_count <= mtrrs.variables.mtrr.len() as u32);

    *mtrr_count = 0;
    for index in 0..variable_mtrr_count as usize {
        let mask = MsrIa32MtrrPhysmaskRegister::from_bits(mtrrs.variables.mtrr[index].mask);
        if mask.v() {
            let base = MsrIa32MtrrPhysbaseRegister::from_bits(mtrrs.variables.mtrr[index].base);
            raw_memory_ranges[*mtrr_count as usize].base_address =
                mtrrs.variables.mtrr[index].base & mtrr_valid_address_mask;
            raw_memory_ranges[*mtrr_count as usize].mem_type = MtrrMemoryCacheType::from(base.mem_type());
            raw_memory_ranges[*mtrr_count as usize].length =
                ((!(mtrrs.variables.mtrr[index].mask & mtrr_valid_address_mask)) & mtrr_valid_bits_mask) + 1;
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

//
//  Return a 32bit random number.
//
//  @param Start  Start of the random number range.
//  @param Limit  Limit of the random number range.
//  @return 32bit random number
//
pub fn random32(start: u32, limit: u32) -> u32 {
    let mut rng = rand::thread_rng();
    rng.gen_range(start..limit)
}

//
//  Return a 64bit random number.
//
//  @param Start  Start of the random number range.
//  @param Limit  Limit of the random number range.
//  @return 64bit random number
//
pub fn random64(start: u64, limit: u64) -> u64 {
    let mut rng = rand::thread_rng();
    rng.gen_range(start..limit)
}

//
//  Generate random MTRR BASE/MASK for a specified type.
//
//  @param PhysicalAddressBits Physical address bits.
//  @param CacheType           Cache type.
//  @param MtrrPair            Return the random MTRR.
//  @param MtrrMemoryRange     Return the random memory range.
//
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

//
//  Check whether the Range overlaps with any one in Ranges.
//
//  @param Range  The memory range to check.
//  @param Ranges The memory ranges.
//  @param Count  Count of memory ranges.
//
//  @return TRUE when overlap exists.
//
fn ranges_overlap(range: &MtrrMemoryRange, ranges: &[MtrrMemoryRange], count: usize) -> bool {
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

//
//  Generate random MTRRs.
//
//  @param PhysicalAddressBits  Physical address bits.
//  @param RawMemoryRanges      Return the randomly generated MTRRs.
//  @param UcCount              Count of Uncacheable MTRRs.
//  @param WtCount              Count of Write Through MTRRs.
//  @param WbCount              Count of Write Back MTRRs.
//  @param WpCount              Count of Write Protected MTRRs.
//  @param WcCount              Count of Write Combine MTRRs.
//
pub fn generate_valid_and_configurable_mtrr_pairs(
    physical_address_bits: u32,
    raw_memory_ranges: &mut [MtrrMemoryRange],
    uc_count: u32,
    wt_count: u32,
    wb_count: u32,
    wp_count: u32,
    wc_count: u32,
) {
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

//
//  Return a random memory cache type.
//
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

//
//  Determin the memory cache type for the Range.
//
//  @param DefaultType Default cache type.
//  @param Range       The memory range to determin the cache type.
//  @param Ranges      The entire memory ranges.
//  @param RangeCount  Count of the entire memory ranges.
//
fn determine_output_memory_cache_type(
    default_type: MtrrMemoryCacheType,
    range: &mut MtrrMemoryRange,
    raw_memory_ranges: &[MtrrMemoryRange],
    raw_memory_ranges_count: u32,
) {
    range.mem_type = MtrrMemoryCacheType::Invalid;
    for index in 0..raw_memory_ranges_count as usize {
        if ranges_overlap(range, &raw_memory_ranges[index..index + 1], 1) {
            if (raw_memory_ranges[index as usize].mem_type as u8) < (range.mem_type as u8) {
                range.mem_type = raw_memory_ranges[index as usize].mem_type;
            }
        }
    }

    if range.mem_type == MtrrMemoryCacheType::Invalid {
        range.mem_type = default_type;
    }
}

//
//  Return TRUE when Address is in the Range.
//
//  @param Address The address to check.
//  @param Range   The range to check.
//  @return TRUE when Address is in the Range.
//
fn address_in_range(address: u64, raw_range: &MtrrMemoryRange) -> bool {
    address >= raw_range.base_address && address <= raw_range.base_address + raw_range.length - 1
}

//
//  Get the overlap bit flag.
//
//  @param RawMemoryRanges     Raw memory ranges.
//  @param RawMemoryRangeCount Count of raw memory ranges.
//  @param Address             The address to check.
//
fn get_overlap_bit_flag(raw_memory_ranges: &[MtrrMemoryRange], raw_memory_range_count: u32, address: u64) -> u64 {
    let mut overlap_bit_flag = 0;
    for index in 0..raw_memory_range_count {
        if address_in_range(address, &raw_memory_ranges[index as usize]) {
            overlap_bit_flag |= 1u64 << index;
        }
    }
    overlap_bit_flag
}

//
//  Return the relationship between flags.
//
//  @param Flag1 Flag 1
//  @param Flag2 Flag 2
//
//  @retval 0   Flag1 == Flag2
//  @retval 1   Flag1 is a subset of Flag2
//  @retval 2   Flag2 is a subset of Flag1
//  @retval 3   No subset relations between Flag1 and Flag2.
//
fn check_overlap_bit_flags_relation(flag1: u64, flag2: u64) -> u32 {
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

//
//  Return TRUE when the Endpoint is in any of the Ranges.
//
//  @param Endpoint    The endpoint to check.
//  @param Ranges      The memory ranges.
//  @param RangeCount  Count of memory ranges.
//
//  @retval TRUE  Endpoint is in one of the range.
//  @retval FALSE Endpoint is not in any of the ranges.
//
fn is_endpoint_in_ranges(endpoint: u64, ranges: &[MtrrMemoryRange], range_count: usize) -> bool {
    for index in 0..range_count {
        if address_in_range(endpoint, &ranges[index]) {
            return true;
        }
    }
    false
}

//
//  Compact adjacent ranges of the same type.
//
//  @param DefaultType                    Default memory type.
//  @param PhysicalAddressBits            Physical address bits.
//  @param EffectiveMtrrMemoryRanges      Memory ranges to compact.
//  @param EffectiveMtrrMemoryRangesCount Return the new count of memory ranges.
//
fn compact_and_extend_effective_mtrr_memory_ranges(
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
            new_ranges[new_ranges_count_actual].length =
                max_address - new_ranges[new_ranges_count_actual].base_address + 1;
            new_ranges[new_ranges_count_actual].mem_type = default_type;
            new_ranges_count_actual += 1;
        }
    }

    *effective_mtrr_memory_ranges = new_ranges;
    *effective_mtrr_memory_ranges_count = new_ranges_count_actual;
}

//
//  Collect all the endpoints in the raw memory ranges.
//
//  @param Endpoints           Return the collected endpoints.
//  @param EndPointCount       Return the count of endpoints.
//  @param RawMemoryRanges     Raw memory ranges.
//  @param RawMemoryRangeCount Count of raw memory ranges.
//
fn collect_endpoints(endpoints: &mut Vec<u64>, raw_memory_ranges: &[MtrrMemoryRange], raw_memory_range_count: usize) {
    assert_eq!(raw_memory_range_count << 1, endpoints.len());

    let mut index = 0;
    let mut index2 = 0;
    while index < raw_memory_range_count {
        let base_address = raw_memory_ranges[index].base_address;
        let length = raw_memory_ranges[index].length;

        if length == 0 {
            index += 1;
            continue;
        }

        endpoints[index2] = base_address;
        endpoints[index2 + 1] = base_address + length - 1;
        index2 += 2;

        index += 1;
    }

    endpoints.shrink_to_fit();
    endpoints.sort_unstable();
    endpoints.dedup();
    endpoints.shrink_to_fit();

    // for i in 0..endpoints.len() {
    //     println!("#### Endpoints[{}] = {:x} \n", i, endpoints[i]);
    // }
}

//
//  Convert the MTRR BASE/MASK array to memory ranges.
//
//  Convert raw unsorted, overlapping ranges to full memory non overlapping
//  ranges.
//
//  @param DefaultType          Default memory type.
//  @param PhysicalAddressBits  Physical address bits.
//  @param RawMemoryRanges      Raw memory ranges.
//  @param RawMemoryRangeCount  Count of raw memory ranges.
//  @param MemoryRanges         Memory ranges.
//  @param MemoryRangeCount     Count of memory ranges.
//
pub fn get_effective_memory_ranges(
    default_type: MtrrMemoryCacheType,
    physical_address_bits: u32,
    raw_memory_ranges: &[MtrrMemoryRange],
    raw_memory_range_count: usize,
    memory_ranges: &mut [MtrrMemoryRange],
    memory_range_count: &mut usize,
) {
    if raw_memory_range_count == 0 {
        memory_ranges[0].base_address = 0;
        memory_ranges[0].length = 1u64 << physical_address_bits;
        memory_ranges[0].mem_type = default_type;
        *memory_range_count = 1;
        return;
    }

    // Input: Raw memory ranges example: Unsorted, can be overlapping, do not
    // cover full memory range.

    //
    // { 0x0000014000000000, 0x0000000400000000, Uncacheable },
    // { 0x0000015800000000, 0x0000000800000000, Uncacheable },
    // { 0x000001dcdfa58000, 0x0000000000001000, Uncacheable },
    // { 0x0000001c00000000, 0x0000000000100000, WriteThrough },
    // { 0x0000007600000000, 0x0000000100000000, WriteThrough },
    // { 0x0000015600000000, 0x0000000000800000, WriteProtected },
    // { 0x0000018000000000, 0x0000004000000000, WriteProtected },
    // { 0x0000017848000000, 0x0000000000800000, WriteCombining },
    // { 0x000000f600000000, 0x0000000000020000, WriteCombining },
    // { 0x0000003400000000, 0x0000000001000000, WriteCombining },
    // { 0x000000e000000000, 0x0000000400000000, WriteCombining },
    //

    // Output: Sorted, non-overlapping, covers full memory range, honors the
    // memory type passed.

    //
    // { 0x0000000000000000, 0x0000001c00000000, WriteBack },
    // { 0x0000001c00000000, 0x0000000000100000, WriteThrough },
    // { 0x0000001c00100000, 0x00000017fff00000, WriteBack },
    // { 0x0000003400000000, 0x0000000001000000, WriteCombining },
    // { 0x0000003401000000, 0x00000041ff000000, WriteBack },
    // { 0x0000007600000000, 0x0000000100000000, WriteThrough },
    // { 0x0000007700000000, 0x0000006900000000, WriteBack },
    // { 0x000000e000000000, 0x0000000400000000, WriteCombining },
    // { 0x000000e400000000, 0x0000001200000000, WriteBack },
    // { 0x000000f600000000, 0x0000000000020000, WriteCombining },
    // { 0x000000f600020000, 0x00000049fffe0000, WriteBack },
    // { 0x0000014000000000, 0x0000000400000000, Uncacheable },
    // { 0x0000014400000000, 0x0000001200000000, WriteBack },
    // { 0x0000015600000000, 0x0000000000800000, WriteProtected },
    // { 0x0000015600800000, 0x00000001ff800000, WriteBack },
    // { 0x0000015800000000, 0x0000000800000000, Uncacheable },
    // { 0x0000016000000000, 0x0000001848000000, WriteBack },
    // { 0x0000017848000000, 0x0000000000800000, WriteCombining },
    // { 0x0000017848800000, 0x00000007b7800000, WriteBack },
    // { 0x0000018000000000, 0x0000004000000000, WriteProtected },
    // { 0x000001c000000000, 0x0000001cdfa58000, WriteBack },
    // { 0x000001dcdfa58000, 0x0000000000001000, Uncacheable },
    // { 0x000001dcdfa59000, 0x00000023205a7000, WriteBack },

    let all_endpoints_count = raw_memory_range_count << 1;
    let mut all_endpoints_inclusive: Vec<u64> = Vec::with_capacity(all_endpoints_count);
    all_endpoints_inclusive.resize(all_endpoints_count, 0);
    let all_range_pieces_count_max = raw_memory_range_count * 3 + 1;
    let mut output_ranges: Vec<MtrrMemoryRange> = Vec::with_capacity(all_range_pieces_count_max);
    output_ranges.resize(all_range_pieces_count_max, MtrrMemoryRange::default());

    println!("all_endpoints_count: {} ", all_endpoints_count);
    collect_endpoints(&mut all_endpoints_inclusive, raw_memory_ranges, raw_memory_range_count);
    println!("all_endpoints_inclusive.len(): {} ", all_endpoints_inclusive.len());

    for i in 0..all_endpoints_inclusive.len() {
        println!("#### AllEndpointsInclusive[{}] = {:x} \n", i, all_endpoints_inclusive[i]);
    }

    let mut output_ranges_count = 0;
    for index in 0..all_endpoints_inclusive.len() - 1 {
        let overlap_bit_flag1 =
            get_overlap_bit_flag(raw_memory_ranges, raw_memory_range_count as u32, all_endpoints_inclusive[index]);
        let overlap_bit_flag2 =
            get_overlap_bit_flag(raw_memory_ranges, raw_memory_range_count as u32, all_endpoints_inclusive[index + 1]);
        let overlap_flag_relation = check_overlap_bit_flags_relation(overlap_bit_flag1, overlap_bit_flag2);

        println!(
            "#### Index = {} OverlapBitFlag1 = {:x}, OverlapBitFlag2 = {:x}, OverlapFlagRelation = {:x} \n",
            index, overlap_bit_flag1, overlap_bit_flag2, overlap_flag_relation
        );

        match overlap_flag_relation {
            0 => {
                // [1, 2]
                output_ranges[output_ranges_count].base_address = all_endpoints_inclusive[index];
                output_ranges[output_ranges_count].length =
                    all_endpoints_inclusive[index + 1] - all_endpoints_inclusive[index] + 1;
                output_ranges_count += 1;
            }
            1 => {
                // [1, 2)
                output_ranges[output_ranges_count].base_address = all_endpoints_inclusive[index];
                output_ranges[output_ranges_count].length =
                    (all_endpoints_inclusive[index + 1] - 1) - all_endpoints_inclusive[index] + 1;
                output_ranges_count += 1;
            }
            2 => {
                // (1, 2]
                output_ranges[output_ranges_count].base_address = all_endpoints_inclusive[index] + 1;
                output_ranges[output_ranges_count].length =
                    all_endpoints_inclusive[index + 1] - (all_endpoints_inclusive[index] + 1) + 1;
                output_ranges_count += 1;

                if !is_endpoint_in_ranges(all_endpoints_inclusive[index], &output_ranges, output_ranges_count) {
                    output_ranges[output_ranges_count].base_address = all_endpoints_inclusive[index];
                    output_ranges[output_ranges_count].length = 1;
                    output_ranges_count += 1;
                }
            }
            3 => {
                // (1, 2)
                output_ranges[output_ranges_count].base_address = all_endpoints_inclusive[index] + 1;
                output_ranges[output_ranges_count].length =
                    (all_endpoints_inclusive[index + 1]) - (all_endpoints_inclusive[index] + 1);
                if output_ranges[output_ranges_count].length == 0 {
                    // Only in case 3 can exists Length=0, we should skip such "segment".

                    // In C, To exit the current switch block and continue the
                    // next iteration of the outer loop we use break statement.
                    // But in Rust, we use continue. Accidentally putting a
                    // break would exit the loop! and debugging this would cost
                    // you a day and a night :-)
                    continue;
                }
                output_ranges_count += 1;

                if !is_endpoint_in_ranges(all_endpoints_inclusive[index], &output_ranges, output_ranges_count) {
                    output_ranges[output_ranges_count].base_address = all_endpoints_inclusive[index];
                    output_ranges[output_ranges_count].length = 1;
                    output_ranges_count += 1;
                }
            }
            _ => panic!("Unexpected overlap flag relation"),
        }
    }

    // Up until this point we only created the required output ranges. But
    // haven't determined their memory types. Now we need to determine the
    // memory cache type for each range piece. We loop over each output range
    // and try to check if overlaps with any of the raw memory ranges. If it
    // does, we set the memory type of the output range to the memory type of
    // the raw memory range it overlaps with. If it doesn't overlap with any
    // raw memory range, we set the memory type of the output range to the
    // default memory type passed to this function.
    for index in 0..output_ranges_count {
        determine_output_memory_cache_type(
            default_type,
            &mut output_ranges[index],
            raw_memory_ranges,
            raw_memory_range_count as u32,
        );
    }
    for i in 0..output_ranges_count {
        println!(
            "#### AllRangePieces[{}] = {:x}, {:x}, {:?} \n",
            i, output_ranges[i].base_address, output_ranges[i].length, output_ranges[i].mem_type
        );
    }

    compact_and_extend_effective_mtrr_memory_ranges(
        default_type,
        physical_address_bits,
        &mut output_ranges,
        &mut output_ranges_count,
    );

    println!("output_ranges_count: {} ", output_ranges_count);
    for i in 0..output_ranges_count {
        println!(
            "#### AllRangePieces[{}] = {:x}, {:x}, {:?} \n",
            i, output_ranges[i].base_address, output_ranges[i].length, output_ranges[i].mem_type
        );
    }
    println!("memory_range_count: {} ", *memory_range_count);
    assert!(*memory_range_count >= output_ranges_count);
    for i in 0..output_ranges_count {
        memory_ranges[i] = output_ranges[i];
    }
    *memory_range_count = output_ranges_count;
}

// Unit tests

#[test]
fn unit_test_get_effective_memory_ranges() {
    let default_type = MtrrMemoryCacheType::Uncacheable;
    let physical_address_bits = 38;
    let raw_memory_ranges = [
        MtrrMemoryRange::new(0x3A0000000, 0x100000, MtrrMemoryCacheType::Uncacheable),
        MtrrMemoryRange::new(0x1C60000000, 0x1000000, MtrrMemoryCacheType::WriteThrough),
        MtrrMemoryRange::new(0x26A0000000, 0x100000, MtrrMemoryCacheType::WriteBack),
    ];
    let raw_memory_range_count = raw_memory_ranges.len();

    let mut expected_memory_ranges = [MtrrMemoryRange::default();
        MTRR_NUMBER_OF_FIXED_MTRR * std::mem::size_of::<u64>() + 2 * MTRR_NUMBER_OF_VARIABLE_MTRR + 1];
    let mut expected_memory_ranges_count: usize = expected_memory_ranges.len();
    get_effective_memory_ranges(
        default_type,
        physical_address_bits,
        &raw_memory_ranges[..],
        raw_memory_range_count,
        &mut expected_memory_ranges,
        &mut expected_memory_ranges_count,
    );

    for index in 0..expected_memory_ranges_count {
        let range = &expected_memory_ranges[index];
        println!("{:x} {:x} {:?}", range.base_address, range.length, range.mem_type)
    }
}
