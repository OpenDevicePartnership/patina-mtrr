//! Test support utilities and helpers for MTRR library unit tests.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]

use crate::structs::{
    MTRR_NUMBER_OF_FIXED_MTRR, MTRR_NUMBER_OF_VARIABLE_MTRR, MsrIa32MtrrPhysbaseRegister, MsrIa32MtrrPhysmaskRegister,
    MtrrMemoryCacheType, MtrrMemoryRange, MtrrSettings, MtrrVariableSetting,
};
use crate::tests::fixtures::{RangeGenerator, TestSequence};

/// Test result collector for MTRR operations.
pub(crate) struct TestResultCollector {
    default_type: MtrrMemoryCacheType,
    physical_address_bits: u32,
    variable_mtrr_count: u32,
}

impl TestResultCollector {
    /// Create a new test result collector.
    pub(crate) fn new(default_type: MtrrMemoryCacheType, physical_address_bits: u32, variable_mtrr_count: u32) -> Self {
        Self { default_type, physical_address_bits, variable_mtrr_count }
    }

    /// Collect test results, returning the number of effective memory ranges and valid MTRRs.
    pub(crate) fn collect_results(&self, mtrrs: &MtrrSettings, ranges: &mut [MtrrMemoryRange]) -> (usize, u32) {
        let mut raw_memory_ranges = [MtrrMemoryRange::default(); MTRR_NUMBER_OF_VARIABLE_MTRR];
        let mtrr_valid_bits_mask = (1u64 << self.physical_address_bits) - 1;
        let mtrr_valid_address_mask = mtrr_valid_bits_mask & !0xFFFu64;

        assert!(self.variable_mtrr_count <= mtrrs.variables.mtrr.len() as u32);

        let mut mtrr_count = 0;
        for index in 0..self.variable_mtrr_count as usize {
            let mask = MsrIa32MtrrPhysmaskRegister::from_bits(mtrrs.variables.mtrr[index].mask);
            if mask.v() {
                let base = MsrIa32MtrrPhysbaseRegister::from_bits(mtrrs.variables.mtrr[index].base);
                raw_memory_ranges[mtrr_count].base_address = mtrrs.variables.mtrr[index].base & mtrr_valid_address_mask;
                raw_memory_ranges[mtrr_count].mem_type = MtrrMemoryCacheType::from(base.mem_type());
                raw_memory_ranges[mtrr_count].length =
                    ((!(mtrrs.variables.mtrr[index].mask & mtrr_valid_address_mask)) & mtrr_valid_bits_mask) + 1;
                mtrr_count += 1;
            }
        }

        let mut range_count = ranges.len();
        get_effective_memory_ranges(
            self.default_type,
            self.physical_address_bits,
            &raw_memory_ranges,
            mtrr_count,
            ranges,
            &mut range_count,
        );

        (range_count, mtrr_count as u32)
    }
}

/// Deterministic test value generator.
#[derive(Debug, Clone)]
pub(crate) struct DeterministicGenerator {
    sequence: TestSequence,
}

impl DeterministicGenerator {
    /// Creates a new deterministic generator starting at the given index.
    pub(crate) fn new(start_index: usize) -> Self {
        Self { sequence: TestSequence::new(start_index) }
    }

    /// Generates a 32-bit test value.
    pub(crate) fn next_u32(&mut self, start: u32, limit: u32) -> u32 {
        self.sequence.next_u32(start, limit)
    }

    /// Generates a 64-bit test value.
    pub(crate) fn next_u64(&mut self, start: u64, limit: u64) -> u64 {
        self.sequence.next_u64(start, limit)
    }

    /// Generates a cache type.
    pub(crate) fn next_cache_type(&mut self) -> MtrrMemoryCacheType {
        self.sequence.next_cache_type()
    }
}

/// MTRR pair generator for creating test configurations.
pub(crate) struct MtrrPairGenerator {
    range_generator: RangeGenerator,
}

impl MtrrPairGenerator {
    /// Creates a new MTRR pair generator.
    pub(crate) fn new(start_index: usize) -> Self {
        Self { range_generator: RangeGenerator::new(TestSequence::new(start_index)) }
    }

    /// Generates an MTRR pair for the given parameters.
    pub(crate) fn generate_pair(
        &mut self,
        physical_address_bits: u32,
        cache_type: MtrrMemoryCacheType,
    ) -> (Option<MtrrVariableSetting>, Option<MtrrMemoryRange>) {
        let (mtrr_pair, memory_range) = self.range_generator.generate_mtrr_pair(physical_address_bits, cache_type);
        (Some(mtrr_pair), Some(memory_range))
    }

    /// Generates multiple valid and configurable MTRR pairs.
    pub(crate) fn generate_multiple_pairs(
        &mut self,
        physical_address_bits: u32,
        type_counts: crate::tests::fixtures::MemoryTypeCounts,
    ) -> Vec<MtrrMemoryRange> {
        self.range_generator.generate_non_overlapping_ranges(physical_address_bits, type_counts)
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
    for i in 0..count {
        if (range.base_address <= ranges[i].base_address && ranges[i].base_address < range.base_address + range.length)
            || (ranges[i].base_address <= range.base_address
                && range.base_address < ranges[i].base_address + ranges[i].length)
        {
            return true;
        }
    }
    false
}

//
//  Determine the memory cache type for the Range.
//
//  @param DefaultType Default cache type.
//  @param Range       The memory range to determine the cache type.
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
        if ranges_overlap(range, &raw_memory_ranges[index..index + 1], 1)
            && (raw_memory_ranges[index].mem_type as u8) < range.mem_type as u8
        {
            range.mem_type = raw_memory_ranges[index].mem_type;
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
    address >= raw_range.base_address && address < raw_range.base_address + raw_range.length
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
#[allow(clippy::slow_vector_initialization)]
pub(crate) fn get_effective_memory_ranges(
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

    let all_endpoints_count = raw_memory_range_count << 1;
    let mut all_endpoints_inclusive: Vec<u64> = Vec::with_capacity(all_endpoints_count);
    all_endpoints_inclusive.resize(all_endpoints_count, 0);
    let all_range_pieces_count_max = raw_memory_range_count * 3 + 1;
    let mut output_ranges: Vec<MtrrMemoryRange> = Vec::with_capacity(all_range_pieces_count_max);
    output_ranges.resize(all_range_pieces_count_max, MtrrMemoryRange::default());

    collect_endpoints(&mut all_endpoints_inclusive, raw_memory_ranges, raw_memory_range_count);

    let mut output_ranges_count = 0;
    for index in 0..all_endpoints_inclusive.len() - 1 {
        let overlap_bit_flag1 =
            get_overlap_bit_flag(raw_memory_ranges, raw_memory_range_count as u32, all_endpoints_inclusive[index]);
        let overlap_bit_flag2 =
            get_overlap_bit_flag(raw_memory_ranges, raw_memory_range_count as u32, all_endpoints_inclusive[index + 1]);
        let overlap_flag_relation = check_overlap_bit_flags_relation(overlap_bit_flag1, overlap_bit_flag2);

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

    for index in 0..output_ranges_count {
        determine_output_memory_cache_type(
            default_type,
            &mut output_ranges[index],
            raw_memory_ranges,
            raw_memory_range_count as u32,
        );
    }

    compact_and_extend_effective_mtrr_memory_ranges(
        default_type,
        physical_address_bits,
        &mut output_ranges,
        &mut output_ranges_count,
    );

    assert!(*memory_range_count >= output_ranges_count);
    for i in 0..output_ranges_count {
        memory_ranges[i] = output_ranges[i];
    }
    *memory_range_count = output_ranges_count;
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn test_deterministic_generator() {
        let mut gen1 = DeterministicGenerator::new(0);
        let mut gen2 = DeterministicGenerator::new(0);

        // Both generators should produce the same sequence
        assert_eq!(gen1.next_u32(0, 100), gen2.next_u32(0, 100));
        assert_eq!(gen1.next_cache_type(), gen2.next_cache_type());
    }

    #[test]
    fn test_test_result_collector() {
        let collector = TestResultCollector::new(MtrrMemoryCacheType::WriteBack, 36, 8);

        let mtrrs = MtrrSettings::default();
        let mut ranges = [MtrrMemoryRange::default(); 100];

        let (range_count, mtrr_count) = collector.collect_results(&mtrrs, &mut ranges);

        // Should have at least one range for the default type
        assert!(range_count > 0);
        assert_eq!(mtrr_count, 0); // There should not be valid MTRRs in the default settings
    }
}
