use core::arch::x86_64::CpuidResult;
use core::arch::x86_64::__cpuid;

use alloc::vec::Vec;
use bitfield_struct::bitfield;
use core::fmt;
use core::fmt::{Display, Formatter};

use crate::error::MtrrError;
use crate::error::MtrrResult;
use crate::reg::{read_msr, write_msr};

// Cache attributes

//
// For X64:
// .-----------------.------.-----.-----.-----.-----.
// |                 | UC   | WC  | WP  | WT  | WB  |
// + --------------- + ---  + --- + --- + --- + --- +
// | Read  Cacheable | no   | no  | yes | yes | yes |
// | Write Cacheable | no   | no* | no  | yes | yes |
// '-----------------'------'-----'-----'-----'-----'
//
// Cache attributes(sorted from not so cache friendly to cache friendly)
pub const EFI_MEMORY_UC: u64 = 0x00000000_00000001u64;
pub const EFI_MEMORY_WC: u64 = 0x00000000_00000002u64;
pub const EFI_MEMORY_WP: u64 = 0x00000000_00001000u64;
pub const EFI_MEMORY_WT: u64 = 0x00000000_00000004u64;
pub const EFI_MEMORY_WB: u64 = 0x00000000_00000008u64;
pub const EFI_MEMORY_UCE: u64 = 0x00000000_00000010u64;

// Variable MTRR msr
const MSR_IA32_MTRR_PHYSBASE0: u32 = 0x00000200;
// const MSR_IA32_MTRR_PHYSBASE1: u32 = 0x00000202;
// const MSR_IA32_MTRR_PHYSBASE2: u32 = 0x00000204;
// const MSR_IA32_MTRR_PHYSBASE3: u32 = 0x00000206;
// const MSR_IA32_MTRR_PHYSBASE4: u32 = 0x00000208;
// const MSR_IA32_MTRR_PHYSBASE5: u32 = 0x0000020A;
// const MSR_IA32_MTRR_PHYSBASE6: u32 = 0x0000020C;
// const MSR_IA32_MTRR_PHYSBASE7: u32 = 0x0000020E;
// const MSR_IA32_MTRR_PHYSBASE8: u32 = 0x00000210;
// const MSR_IA32_MTRR_PHYSBASE9: u32 = 0x00000212;

const MSR_IA32_MTRR_PHYSMASK0: u32 = 0x00000201;
// const MSR_IA32_MTRR_PHYSMASK1: u32 = 0x00000203;
// const MSR_IA32_MTRR_PHYSMASK2: u32 = 0x00000205;
// const MSR_IA32_MTRR_PHYSMASK3: u32 = 0x00000207;
// const MSR_IA32_MTRR_PHYSMASK4: u32 = 0x00000209;
// const MSR_IA32_MTRR_PHYSMASK5: u32 = 0x0000020B;
// const MSR_IA32_MTRR_PHYSMASK6: u32 = 0x0000020D;
// const MSR_IA32_MTRR_PHYSMASK7: u32 = 0x0000020F;
// const MSR_IA32_MTRR_PHYSMASK8: u32 = 0x00000211;
// const MSR_IA32_MTRR_PHYSMASK9: u32 = 0x00000213;

// Fixed MTRR msr
const MSR_IA32_MTRR_FIX64K_00000: u32 = 0x00000250;
const MSR_IA32_MTRR_FIX16K_80000: u32 = 0x00000258;
const MSR_IA32_MTRR_FIX16K_A0000: u32 = 0x00000259;
const MSR_IA32_MTRR_FIX4K_C0000: u32 = 0x00000268;
const MSR_IA32_MTRR_FIX4K_C8000: u32 = 0x00000269;
const MSR_IA32_MTRR_FIX4K_D0000: u32 = 0x0000026A;
const MSR_IA32_MTRR_FIX4K_D8000: u32 = 0x0000026B;
const MSR_IA32_MTRR_FIX4K_E0000: u32 = 0x0000026C;
const MSR_IA32_MTRR_FIX4K_E8000: u32 = 0x0000026D;
const MSR_IA32_MTRR_FIX4K_F0000: u32 = 0x0000026E;
const MSR_IA32_MTRR_FIX4K_F8000: u32 = 0x0000026F;

const MSR_IA32_MTRR_DEF_TYPE: u32 = 0x000002FF;

const MSR_IA32_MTRRCAP: u32 = 0x000000FE;

#[bitfield(u64)]
pub struct MtrrPhyBase {
    #[bits(8)]
    pub mem_type: u8,
    #[bits(4)]
    pub reserved1: u8,
    #[bits(40)]
    pub base_address: u64,
    #[bits(12)]
    pub reserved2: u16,
}

#[bitfield(u64)]
pub struct MtrrPhyMask {
    #[bits(11)]
    pub reserved1: u16,
    #[bits(1)]
    pub valid: u8,
    #[bits(40)]
    pub mask: u64,
    #[bits(12)]
    pub reserved2: u16,
}

// pub const MTRR_MEMORY_TYPE_UNCACHEABLE: u8 = 0x0;
// pub const MTRR_MEMORY_TYPE_WRITE_COMBINING: u8 = 0x1;
// pub const MTRR_MEMORY_TYPE_WRITE_THROUGH: u8 = 0x4;
// pub const MTRR_MEMORY_TYPE_WRITE_PROTECT: u8 = 0x5;
// pub const MTRR_MEMORY_TYPE_WRITE_BACK: u8 = 0x6;
#[derive(PartialEq, Clone, Copy, Debug)]
enum MtrrMemoryType {
    Uncacheable = 0x0,
    WriteCombining = 0x1,
    WriteThrough = 0x4,
    WriteProtect = 0x5,
    WriteBack = 0x6,
}

impl From<u64> for MtrrMemoryType {
    fn from(value: u64) -> MtrrMemoryType {
        match value {
            0 => MtrrMemoryType::Uncacheable,
            1 => MtrrMemoryType::WriteCombining,
            4 => MtrrMemoryType::WriteThrough,
            5 => MtrrMemoryType::WriteProtect,
            6 => MtrrMemoryType::WriteBack,
            _ => panic!("Invalid value for MtrrMemoryType: {}", value),
        }
    }
}

impl From<u8> for MtrrMemoryType {
    fn from(value: u8) -> MtrrMemoryType {
        (value as u64).into()
    }
}

const SIZE_1MB: u32 = 0x000100000;
const SIZE_64KB: u32 = 0x00010000;
const SIZE_16KB: u32 = 0x00004000;
const SIZE_4KB: u32 = 0x00001000;

struct MtrrFixedRange {
    mtrr_msr: u32,
    base: u32,
    size: u32,
    mtrr_msr_value: u64,
    needs_update: bool,
}

impl MtrrFixedRange {
    pub const fn new(mtrr_msr: u32, base: u32, size: u32) -> Self {
        Self { mtrr_msr, base, size, mtrr_msr_value: 0, needs_update: false }
    }
}

struct MtrrRange {
    base_address: u64,
    length: u64,
    mem_type: MtrrMemoryType,
}

impl MtrrRange {
    pub fn new(base_address: u64, length: u64, mem_type: MtrrMemoryType) -> Self {
        Self { base_address, length, mem_type }
    }
}

impl Display for MtrrRange {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        write!(
            fmt,
            "[base: 0x{:016X}, length: 0x{:016X}, mem_type: 0x{:?}]",
            self.base_address, self.length, self.mem_type
        )
    }
}

struct MtrrCap {
    variable_range_register_count: u8,
    fixed_range_register_supported: bool,
    write_combining_supported: bool,
}

struct MtrrDefType {
    default_mem_type: MtrrMemoryType,
    fixed_range_enable: u8,
    mtrr_enable: u8,
}

fn mtrr_is_enabled() -> bool {
    #[cfg(not(feature = "no-reg-rw"))]
    {
        let leaf = 0x1;
        let CpuidResult { edx, .. } = unsafe { __cpuid(leaf) };

        // 12th bit is not enabled if Memory Type Range Registers is not supported.
        if (edx >> 12) & 1 == 0 {
            return false;
        }

        // if mtrr is supported check the support level(fixed vs variable)
        let mtrr_cap = mtrr_get_mtrrcap();
        // neither fixed not variable is supported
        if !mtrr_cap.fixed_range_register_supported || mtrr_cap.variable_range_register_count == 0 {
            return false;
        }
    }

    true
}

fn mtrr_fixed_range_is_supported() -> bool {
    #[cfg(not(feature = "no-reg-rw"))]
    {
        let mtrrcap = mtrr_get_mtrrcap();
        mtrrcap.fixed_range_register_supported == true
    }
    #[cfg(feature = "no-reg-rw")]
    {
        true
    }
}

fn mtrr_get_mtrrcap() -> MtrrCap {
    #[cfg(not(feature = "no-reg-rw"))]
    {
        let mtrrcap_reg = unsafe { read_msr(MSR_IA32_MTRRCAP) };

        MtrrCap {
            variable_range_register_count: (mtrrcap_reg & 0xFF) as u8,
            fixed_range_register_supported: ((mtrrcap_reg >> 8) & 1) == 1,
            write_combining_supported: ((mtrrcap_reg >> 10) & 1) == 1,
        }
    }
    #[cfg(feature = "no-reg-rw")]
    {
        MtrrCap {
            variable_range_register_count: 8,
            fixed_range_register_supported: true,
            write_combining_supported: true,
        }
    }
}

fn mtrr_get_mtrrdef() -> MtrrDefType {
    #[cfg(not(feature = "no-reg-rw"))]
    {
        let mtrrdef_reg = unsafe { read_msr(MSR_IA32_MTRR_DEF_TYPE) };

        MtrrDefType {
            default_mem_type: (mtrrdef_reg & 0xFF).into(),
            fixed_range_enable: ((mtrrdef_reg >> 10) & 1) as u8,
            mtrr_enable: ((mtrrdef_reg >> 11) & 1) as u8,
        }
    }
    #[cfg(feature = "no-reg-rw")]
    {
        MtrrDefType {
            default_mem_type: MtrrMemoryType::WriteBack,
            fixed_range_enable: ((mtrrdef_reg >> 10) & 1) as u8,
            mtrr_enable: ((mtrrdef_reg >> 11) & 1) as u8,
        }
    }
}

fn mtrr_get_valid_address_mask() -> (u64, u64) {
    let cpuid_extended_info_leaf = 0x80000000;
    let cpuid_vir_phy_address_width_leaf = 0x80000008; // Processor Capacity Parameters and Extended Feature Identification
    let max_extended_function = unsafe { __cpuid(cpuid_extended_info_leaf).eax };
    let max_phy_address_width;
    if max_extended_function >= cpuid_vir_phy_address_width_leaf {
        max_phy_address_width = unsafe { (__cpuid(cpuid_vir_phy_address_width_leaf).eax & 0xFF) as u64 };
    } else {
        max_phy_address_width = 36;
    }

    // TODO: incorporate TME-MK logic

    let valid_bit_mask = (1 << max_phy_address_width) - 1;
    let valid_address_mask = valid_bit_mask & 0xffff_ffff_ffff_f000;

    (valid_bit_mask, valid_address_mask)
}

fn mtrr_validate_ranges(ranges: &Vec<MtrrRange>) -> MtrrResult<()> {
    let (valid_bit_mask, valid_address_mask) = mtrr_get_valid_address_mask();
    for range in ranges {
        if range.base_address & valid_address_mask != 0 {
            return Err(MtrrError::InvalidMemoryRange);
        }

        // address + length should either fall with in the valid address range
        // or it should be the max (this happens when the full range is requested)
        if (range.base_address + range.length) & !valid_address_mask != 0
            && (range.base_address + range.length) != valid_bit_mask + 1
        {
            return Err(MtrrError::InvalidMemoryRange);
        }
    }

    Ok(())
}

fn mtrr_read_active_ranges() -> Vec<MtrrRange> {
    let mut ranges: Vec<MtrrRange> = Vec::new();
    let (valid_bit_mask, valid_address_mask) = mtrr_get_valid_address_mask();
    let variable_range_register_count = mtrr_get_mtrrcap().variable_range_register_count;

    let phy_base_msr = MSR_IA32_MTRR_PHYSBASE0;
    let phy_mask_msr = MSR_IA32_MTRR_PHYSMASK0;

    for i in 0..variable_range_register_count as u32 {
        let phy_mask_msr_value = unsafe { read_msr(phy_mask_msr + 2 * i) };
        let valid = (phy_mask_msr_value >> 11) & 1 == 1;
        if valid {
            let phy_base_msr_value = unsafe { read_msr(phy_base_msr + 2 * i) };
            let base_address = valid_address_mask;
            let length = (!(phy_mask_msr_value & valid_address_mask) & valid_bit_mask) + 1;
            let mem_type = phy_base_msr_value & 0xff;
            ranges.push(MtrrRange { base_address, length, mem_type: mem_type.into() });
        }
    }

    ranges
}

fn mtrr_set_variable_range_memory_attributes(address: u64, length: u64, mem_type: MtrrMemoryType) -> MtrrResult<()> {
    let original_ranges = mtrr_read_active_ranges();

    Ok(())
}
// fn mtrr_write_active_ranges(ranges: &Vec<MtrrRange>) {
//     let variable_range_register_count = mtrr_get_mtrrcap().variable_range_register_count;

//     let phy_base_msr = MSR_IA32_MTRR_PHYSBASE0;
//     let phy_mask_msr = MSR_IA32_MTRR_PHYSMASK0;

//     for i in 0..variable_range_register_count as u32 {
//         let phy_base_msr_value = MtrrPhyBase::from_bits(unsafe { read_msr(phy_base_msr + 2 * i) });
//         let phy_mask_msr_value = MtrrPhyMask::from_bits(unsafe { read_msr(phy_mask_msr + 2 * i) });
//         ranges.push(MtrrRange {
//             base_address: phy_base_msr_value.base_address(),
//             length: (!phy_mask_msr_value.mask()) + 1,
//             mem_type: phy_base_msr_value.mem_type().into(),
//         });
//     }
// }

pub fn mtrr_set_attributes(ranges: &mut Vec<MtrrRange>) -> MtrrResult<()> {
    if !mtrr_is_enabled() {
        return Err(MtrrError::MtrrDisabled);
    }

    mtrr_validate_ranges(ranges)?;

    let mtrr_fixed_range_supported = mtrr_fixed_range_is_supported();
    for range in ranges {
        let address = range.base_address;
        let length = range.length;
        let mem_type = range.mem_type;

        if mtrr_fixed_range_supported {
            if address + length - 1 < SIZE_1MB as u64 {
                // in fixed range
                let _ = mtrr_set_fixed_range_memory_attributes(address as u32, length as u32, mem_type);
            } else if address >= SIZE_1MB as u64 {
                // in variable range
                let _ = mtrr_set_variable_range_memory_attributes(address, length, mem_type);
            } else {
                //split the overlapping range
                let address = range.base_address;
                let length = SIZE_1MB as u64 - address;
                let _ = mtrr_set_fixed_range_memory_attributes(address as u32, length as u32, mem_type);

                let address = SIZE_1MB as u64;
                let length = range.length - SIZE_1MB as u64;
                let _ = mtrr_set_variable_range_memory_attributes(address, length, mem_type);
            }
        } else {
            let _ = mtrr_set_variable_range_memory_attributes(address, length, mem_type);
        }
    }
    Ok(())
}

pub fn mtrr_get_attributes(_address: u64, _size: u64) -> MtrrResult<u8> {
    // TODO: implement setting mtrr variable memory ranges
    Ok(0)
}

pub fn mtrr_dump() {}

fn get_mtrr_fixed_ranges() -> [MtrrFixedRange; 12] {
    // Fixed-Range MTRR Address Ranges
    // |63-56      |55-48      |47-40      |39-32      |31-24      |23-16      |15-8       |7-0        |Register Name(MSR)|
    // +-----------+-----------+-----------+-----------+-----------+-----------+-----------+-----------+------------------+
    // |70000-7FFFF|60000-6FFFF|50000-5FFFF|40000-4FFFF|30000-3FFFF|20000-2FFFF|10000-1FFFF|00000-0FFFF|MTRRfix64K_00000  |
    // |9C000-9FFFF|98000-9BFFF|94000-97FFF|90000-93FFF|8C000-8FFFF|88000-8BFFF|84000-87FFF|80000-83FFF|MTRRfix16K_80000  |
    // |BC000-BFFFF|B8000-BBFFF|B4000-B7FFF|B0000-B3FFF|AC000-AFFFF|A8000-ABFFF|A4000-A7FFF|A0000-A3FFF|MTRRfix16K_A0000  |
    // |C7000-C7FFF|C6000-C6FFF|C5000-C5FFF|C4000-C4FFF|C3000-C3FFF|C2000-C2FFF|C1000-C1FFF|C0000-C0FFF|MTRRfix4K_C0000   |
    // |CF000-CFFFF|CE000-CEFFF|CD000-CDFFF|CC000-CCFFF|CB000-CBFFF|CA000-CAFFF|C9000-C9FFF|C8000-C8FFF|MTRRfix4K_C8000   |
    // |D7000-D7FFF|D6000-D6FFF|D5000-D5FFF|D4000-D4FFF|D3000-D3FFF|D2000-D2FFF|D1000-D1FFF|D0000-D0FFF|MTRRfix4K_D0000   |
    // |DF000-DFFFF|DE000-DEFFF|DD000-DDFFF|DC000-DCFFF|DB000-DBFFF|DA000-DAFFF|D9000-D9FFF|D8000-D8FFF|MTRRfix4K_D8000   |
    // |E7000-E7FFF|E6000-E6FFF|E5000-E5FFF|E4000-E4FFF|E3000-E3FFF|E2000-E2FFF|E1000-E1FFF|E0000-E0FFF|MTRRfix4K_E0000   |
    // |EF000-EFFFF|EE000-EEFFF|ED000-EDFFF|EC000-ECFFF|EB000-EBFFF|EA000-EAFFF|E9000-E9FFF|E8000-E8FFF|MTRRfix4K_E8000   |
    // |F7000-F7FFF|F6000-F6FFF|F5000-F5FFF|F4000-F4FFF|F3000-F3FFF|F2000-F2FFF|F1000-F1FFF|F0000-F0FFF|MTRRfix4K_F0000   |
    // |FF000-FFFFF|FE000-FEFFF|FD000-FDFFF|FC000-FCFFF|FB000-FBFFF|FA000-FAFFF|F9000-F9FFF|F8000-F8FFF|MTRRfix4K_F8000   |
    // |E7000-E7FFF|E6000-E6FFF|E5000-E5FFF|E4000-E4FFF|E3000-E3FFF|E2000-E2FFF|E1000-E1FFF|E0000-E0FFF|MTRRfix4K_E0000   |
    // |EF000-EFFFF|EE000-EEFFF|ED000-EDFFF|EC000-ECFFF|EB000-EBFFF|EA000-EAFFF|E9000-E9FFF|E8000-E8FFF|MTRRfix4K_E8000   |
    // |F7000-F7FFF|F6000-F6FFF|F5000-F5FFF|F4000-F4FFF|F3000-F3FFF|F2000-F2FFF|F1000-F1FFF|F0000-F0FFF|MTRRfix4K_F0000   |
    // |FF000-FFFFF|FE000-FEFFF|FD000-FDFFF|FC000-FCFFF|FB000-FBFFF|FA000-FAFFF|F9000-F9FFF|F8000-F8FFF|MTRRfix4K_F8000   |
    [
        MtrrFixedRange::new(MSR_IA32_MTRR_FIX64K_00000, 0x00000, SIZE_64KB),
        MtrrFixedRange::new(MSR_IA32_MTRR_FIX16K_80000, 0x80000, SIZE_16KB),
        MtrrFixedRange::new(MSR_IA32_MTRR_FIX16K_A0000, 0xA0000, SIZE_16KB),
        MtrrFixedRange::new(MSR_IA32_MTRR_FIX4K_C0000, 0xC0000, SIZE_4KB),
        MtrrFixedRange::new(MSR_IA32_MTRR_FIX4K_C8000, 0xC8000, SIZE_4KB),
        MtrrFixedRange::new(MSR_IA32_MTRR_FIX4K_D0000, 0xD0000, SIZE_4KB),
        MtrrFixedRange::new(MSR_IA32_MTRR_FIX4K_D8000, 0xD8000, SIZE_4KB),
        MtrrFixedRange::new(MSR_IA32_MTRR_FIX4K_E0000, 0xE0000, SIZE_4KB),
        MtrrFixedRange::new(MSR_IA32_MTRR_FIX4K_E8000, 0xE8000, SIZE_4KB),
        MtrrFixedRange::new(MSR_IA32_MTRR_FIX4K_F0000, 0xF0000, SIZE_4KB),
        MtrrFixedRange::new(MSR_IA32_MTRR_FIX4K_F8000, 0xF8000, SIZE_4KB),
        MtrrFixedRange::new(0, 0x100000, SIZE_4KB),
    ]
}

/// Function to update mtrr fixed range memory attributes ie., memory ranges below < 1MB
fn mtrr_set_fixed_range_memory_attributes(address: u32, length: u32, mem_type: MtrrMemoryType) -> MtrrResult<()> {
    if !mtrr_fixed_range_is_supported() {
        return Err(MtrrError::MtrrDisabled);
    }

    let mut fixed_ranges = get_mtrr_fixed_ranges();

    mtrr_set_fixed_range_memory_attributes_internal(address, length, mem_type, &mut fixed_ranges)?;

    // Program the updated mtrr MSRs
    for range in fixed_ranges {
        if range.needs_update {
            unsafe { write_msr(range.mtrr_msr, range.mtrr_msr_value) };
        }
    }

    Ok(())
}

/// Function performs the actual ranges of mtrr fixed msr that need to be
/// updated for the given range. The function is separated from its non internal
/// version to make the logic unit testable.
fn mtrr_set_fixed_range_memory_attributes_internal(
    mut address: u32,
    length: u32,
    mem_type: MtrrMemoryType,
    fixed_ranges: &mut [MtrrFixedRange; 12],
) -> MtrrResult<(u32, u32)> {
    let fixed_ranges_len = fixed_ranges.len();

    if length == 0 {
        // panic!("length cannot be zero");
        return Err(MtrrError::InvalidMemoryRange);
    }

    // check memory bounds
    if address >= fixed_ranges[fixed_ranges_len - 1].base
        || address + length - 1 >= fixed_ranges[fixed_ranges_len - 1].base
    {
        // panic!("address or address + length cannot be greater than 1MB");
        return Err(MtrrError::Above1MBMemoryRange);
    }

    // find the lowest fixed mtrr for the given address
    let mut min = 0;
    while min < fixed_ranges_len - 1 {
        if address >= fixed_ranges[min + 1].base {
            min += 1;
        } else {
            break;
        }
    }

    // find the highest fixed mtrr for the given address + length
    let mut max = fixed_ranges_len;
    while max - 1 > 0 {
        if address + length - 1 < fixed_ranges[max - 1].base {
            max -= 1;
        } else {
            break;
        }
    }

    fn is_aligned(address: u32, alignment: u32) -> bool {
        (address & (alignment - 1)) == 0
    }

    // check if the address is aligned with the fixed_ranges[min] alignment
    if !is_aligned(address, fixed_ranges[min].size) {
        return Err(MtrrError::UnalignedAddress);
    }

    // check if the address + length is aligned with the fixed_ranges[max - 1] alignment
    if !is_aligned(address + length, fixed_ranges[max - 1].size) {
        return Err(MtrrError::UnalignedMemoryRange);
    }

    // Find MTRR sub ranges
    let mut i = min;
    while i < max {
        let base = fixed_ranges[i].base;
        let next_base = fixed_ranges[i + 1].base;

        // Each fixed MTRR is a 64 bit MSR. With in this 64 bit register, each
        // byte(total 8 bytes) will represent the memory type for the sub range
        // of memory as per the above table.

        // So for the given memory range, we try to calculate the number of
        // slots from the right that should not be touched(as they are outside
        // the given memory range). This can occur if the given memory range do
        // not start exactly at the MSR range.
        let num_right_slots = address.abs_diff(base) / fixed_ranges[i].size;

        // Then we also try to calculate the number of slots from the left that
        // should not be touched(as they are outside the given memory range).
        // This can occur if the given memory range do not fully occupy the
        // entire MSR range.
        let mut num_left_slots = 0;
        if address + length < next_base {
            num_left_slots = (address + length).abs_diff(next_base) / fixed_ranges[i].size;
        }

        // Read the current MSR and save it in to fixed ranges[i]
        let mut mtrr_msr_value = unsafe { read_msr(fixed_ranges[i].mtrr_msr) };
        fixed_ranges[i].mtrr_msr_value = mtrr_msr_value;

        // Update the used memory slots of MTRR with mem type
        for slot in num_right_slots..(8 - num_left_slots) {
            mtrr_msr_value |= (mem_type as u64) << (8 * slot);
        }

        // If update is needed then store the value and mark it as such
        if fixed_ranges[i].mtrr_msr_value != mtrr_msr_value {
            fixed_ranges[i].mtrr_msr_value = mtrr_msr_value;
            fixed_ranges[i].needs_update = true;
        }

        // Move to the next memory range
        address = next_base;
        i += 1;
    }

    // return the range of the fixed mtrr to be programmed
    Ok((min as u32, max as u32))
    // return the actual registers with the masks sets
}

fn range_starts_in(range: &MtrrRange, new_range: &MtrrRange) -> bool {
    // check if start of the new range falls inside the current range
    range.base_address <= new_range.base_address && new_range.base_address <= range.base_address + range.length - 1
}

fn range_ends_in(range: &MtrrRange, new_range: &MtrrRange) -> bool {
    // check if end of the new range falls inside the current range
    let new_range_end_address = new_range.base_address + new_range.length - 1;
    range.base_address <= new_range_end_address && new_range_end_address <= range.base_address + range.length - 1
}

// This function takes a new range and tries to appropriately fit it in side
// existing ranges, in the process, some of the existing ranges need to be
// collapsed if the new range overlap them. And also, adding a new range might
// lead to merging with neighbouring ranges matching with its memory type.
//
// case 1: new range completely fit/overlap an existing range(start == end)
//      v------new range base
// -----+------------+-----
//      '▓▓▓▓▓▓▓▓▓▓▓▓'
//      '▓▓▓▓▓▓▓▓▓▓▓▓'
// -----+------------+-----
//      ^---existing range base
//
// case 2: new range begins with an existing range(start == end)
//      v------new range base
// -----+-----.----+-----
//      '▓▓▓▓▓'    +
//      '▓▓▓▓▓'    +
// -----+-----'----+-----
//      ^---existing range base
//
// case 3: new range ends with an existing range(start == end)
//            v------new range base
// -----+-----.-----+-----
//      +     '▓▓▓▓▓'
//      +     '▓▓▓▓▓'
// -----+-----'-----+-----
//      ^---existing range base
//
// case 4: new range contains with in an existing range(start == end)
//            v------new range base
// -----+-----.-----.----+-----
//      +     '▓▓▓▓▓'    +
//      +     '▓▓▓▓▓'    +
// -----+-----'-----'----+-----
//      ^---existing range base
//
// case 5: new range overlaps with multiple existing ranges(start != end)
//            v------new range base
// -----+-----.----------+---------+---------+--.-------+-----
//      +     '▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓'       +
//      +     '▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓'       +
// -----+-----'----------+---------+---------+--'-------+-----
//      ^---existing start range base        ^---existing end range base
//
fn split_and_merge_ranges(ranges: &mut Vec<MtrrRange>, new_range: &MtrrRange, start: usize, mut end: usize) {
    // case 5: collapse any intermediate ranges(not including the end range)
    while start + 1 < end {
        ranges[start].length += ranges[start + 1].length;
        ranges.remove(start + 1);
        end = end - 1;
    }

    // case 5: handling of end range is special if the mem type do not match
    if start + 1 == end {
        // mem type match to merge it
        if ranges[start].mem_type == ranges[end].mem_type {
            ranges[start].length += ranges[start + 1].length;
            ranges.remove(start + 1);
        } else {
            // mem type do not match so split it accordingly.
            // length of new range extending in to the end range
            let length = new_range.base_address + new_range.length - ranges[end].base_address;
            ranges[start].length += length;
            ranges[end].base_address += length;
            ranges[end].length -= length;
        }
    }

    // we now have to deal with case 1-4.
    let mut curr = start;
    let left_length = new_range.base_address - ranges[curr].base_address;
    let right_length = (ranges[curr].base_address + ranges[curr].length) - (new_range.base_address + new_range.length);

    if left_length != 0 {
        // create left range prior to the current range
        let left_range =
            MtrrRange { base_address: ranges[curr].base_address, length: left_length, mem_type: ranges[curr].mem_type };

        ranges.insert(curr, left_range);
        curr += 1;
    }

    if right_length != 0 {
        // create right range next to the current range
        let right_range = MtrrRange {
            base_address: new_range.base_address + new_range.length,
            length: right_length,
            mem_type: ranges[curr].mem_type,
        };

        ranges.insert(curr + 1, right_range);
    }

    // adjust the current range
    ranges[curr].base_address = new_range.base_address;
    ranges[curr].length = ranges[curr].length - left_length - right_length;
    ranges[curr].mem_type = new_range.mem_type;

    // Merge neighboring ranges if required.

    // not the last range
    if curr != ranges.len() - 1 {
        let right = curr + 1;
        if ranges[curr].mem_type == ranges[right].mem_type {
            ranges[curr].length += ranges[right].length;
            ranges.remove(right);
        }
    }

    // not the first range
    if curr != 0 {
        let left = curr - 1;
        if ranges[left].mem_type == ranges[curr].mem_type {
            ranges[left].length += ranges[curr].length;
            ranges.remove(curr);
        }
    }
}

fn update_ranges(ranges: &mut Vec<MtrrRange>, new_range: &MtrrRange) {
    let mut start = 0;
    let mut end = 0;
    for (i, range) in ranges.iter().enumerate() {
        if range_starts_in(range, &new_range) {
            start = i;
        }

        if range_ends_in(range, &new_range) {
            end = i;
        }
    }

    split_and_merge_ranges(ranges, new_range, start, end);
}

fn main() {}

#[cfg(test)]
mod tests {
    use crate::mtrr::MtrrMemoryType;

    use super::{get_mtrr_fixed_ranges, mtrr_set_fixed_range_memory_attributes_internal, MtrrRange};
    // --------------------------- Fixed Range Tests ------------------------
    #[test]
    fn test_non_overlapping_ranges() {
        // MTRRfix64K_00000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x00000,
                0x10000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((0, 1))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x10000,
                0x10000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((0, 1))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x20000,
                0x10000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((0, 1))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x30000,
                0x10000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((0, 1))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x40000,
                0x10000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((0, 1))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x50000,
                0x10000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((0, 1))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x60000,
                0x10000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((0, 1))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x70000,
                0x10000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((0, 1))
        );

        // MTRRfix16K_80000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x80000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((1, 2))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x84000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((1, 2))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x88000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((1, 2))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x8C000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((1, 2))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x90000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((1, 2))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x94000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((1, 2))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x98000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((1, 2))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x9C000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((1, 2))
        );

        // MTRRfix16K_A0000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xA0000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((2, 3))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xA4000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((2, 3))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xA8000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((2, 3))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xAC000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((2, 3))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xB0000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((2, 3))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xB4000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((2, 3))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xB8000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((2, 3))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xBC000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((2, 3))
        );

        // MTRRfix4K_C0000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xC0000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((3, 4))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xC1000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((3, 4))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xC2000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((3, 4))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xC3000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((3, 4))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xC4000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((3, 4))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xC5000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((3, 4))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xC6000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((3, 4))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xC7000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((3, 4))
        );

        // MTRRfix4K_C8000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xC8000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((4, 5))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xC9000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((4, 5))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xCA000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((4, 5))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xCB000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((4, 5))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xCC000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((4, 5))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xCD000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((4, 5))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xCE000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((4, 5))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xCF000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((4, 5))
        );

        // MTRRfix4K_D0000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xD0000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((5, 6))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xD1000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((5, 6))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xD2000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((5, 6))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xD3000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((5, 6))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xD4000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((5, 6))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xD5000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((5, 6))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xD6000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((5, 6))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xD7000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((5, 6))
        );

        // MTRRfix4K_D8000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xD8000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((6, 7))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xD9000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((6, 7))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xDA000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((6, 7))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xDB000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((6, 7))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xDC000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((6, 7))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xDD000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((6, 7))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xDE000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((6, 7))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xDF000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((6, 7))
        );

        // MTRRfix4K_E0000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xE0000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((7, 8))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xE1000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((7, 8))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xE2000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((7, 8))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xE3000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((7, 8))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xE4000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((7, 8))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xE5000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((7, 8))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xE6000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((7, 8))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xE7000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((7, 8))
        );

        // MTRRfix4K_E8000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xE8000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((8, 9))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xE9000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((8, 9))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xEA000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((8, 9))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xEB000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((8, 9))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xEC000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((8, 9))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xED000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((8, 9))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xEE000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((8, 9))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xEF000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((8, 9))
        );

        // MTRRfix4K_F0000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xF0000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((9, 10))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xF1000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((9, 10))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xF2000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((9, 10))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xF3000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((9, 10))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xF4000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((9, 10))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xF5000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((9, 10))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xF6000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((9, 10))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xF7000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((9, 10))
        );

        // MTRRfix4K_F8000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xF8000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((10, 11))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xF9000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((10, 11))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xFA000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((10, 11))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xFB000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((10, 11))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xFC000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((10, 11))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xFD000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((10, 11))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xFE000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((10, 11))
        );
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xFF000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((10, 11))
        );
    }

    #[test]
    fn test_overlapping_but_with_in_single_fixed_mtr_range() {
        // MTRRfix64K_00000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x00000,
                0x10000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((0, 1))
        );

        // MTRRfix16K_80000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x80000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((1, 2))
        );

        // MTRRfix16K_A0000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xA0000,
                0x4000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((2, 3))
        );

        // MTRRfix4K_C0000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xC0000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((3, 4))
        );

        // MTRRfix4K_C8000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xC8000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((4, 5))
        );

        // MTRRfix4K_D0000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xD0000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((5, 6))
        );

        // MTRRfix4K_D8000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xD8000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((6, 7))
        );

        // MTRRfix4K_E0000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xE0000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((7, 8))
        );

        // MTRRfix4K_E8000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xE8000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((8, 9))
        );

        // MTRRfix4K_F0000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xF0000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((9, 10))
        );

        // MTRRfix4K_F8000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0xF8000,
                0x1000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((10, 11))
        );
    }

    #[test]
    fn test_overlapping_full_fixed_mtr_range() {
        // Full range
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x00000,
                0x100000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((0, 11))
        );
    }

    #[test]
    fn test_overlapping_partial_fixed_mtr_range() {
        // MTRRfix64K_00000 + MTRRfix16K_80000
        assert_eq!(
            mtrr_set_fixed_range_memory_attributes_internal(
                0x00000,
                0x84000,
                MtrrMemoryType::WriteBack,
                &mut get_mtrr_fixed_ranges()
            ),
            Ok((0, 2))
        );
    }

    #[test]
    fn negative_test_length_zero() {
        // MTRRfix64K_00000 + MTRRfix16K_80000

        let res = mtrr_set_fixed_range_memory_attributes_internal(
            0x80000,
            0,
            MtrrMemoryType::WriteBack,
            &mut get_mtrr_fixed_ranges(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn negative_test_length_above_1mb() {
        // length > 1mb
        let res = mtrr_set_fixed_range_memory_attributes_internal(
            0x00000,
            0x200000,
            MtrrMemoryType::WriteBack,
            &mut get_mtrr_fixed_ranges(),
        );
        assert!(res.is_err());

        // address + length > 1mb
        let res = mtrr_set_fixed_range_memory_attributes_internal(
            0x200000,
            0x1,
            MtrrMemoryType::WriteBack,
            &mut get_mtrr_fixed_ranges(),
        );
        assert!(res.is_err());
    }

    // --------------------------- Fixed Range Tests ------------------------

    use std::collections::HashSet;

    use alloc::vec::Vec;
    use rand::Rng;

    use super::update_ranges;

    const MAX: u64 = 0xffff_ffff_ffff_ffff;

    fn get_random_mtrr_ranges(num_splits: usize) -> Vec<MtrrRange> {
        let mut rng = rand::thread_rng();
        let max_value = MAX;
        let mut breakpoints = HashSet::new();

        let mtrr_mem_type = [0u8, 1, 4, 5, 6];

        while breakpoints.len() < num_splits - 1 {
            breakpoints.insert(rng.gen_range(1..max_value));
        }

        let mut breakpoints: Vec<u64> = breakpoints.into_iter().collect();
        breakpoints.sort_unstable();

        let mut ranges = Vec::new();
        let mut start = 0;

        for &end in breakpoints.iter() {
            ranges.push(MtrrRange::new(
                start,
                end - start,
                mtrr_mem_type[rng.gen_range(0..mtrr_mem_type.len())].into(),
            ));
            start = end;
        }

        ranges.push(MtrrRange::new(
            start,
            max_value - start,
            mtrr_mem_type[rng.gen_range(0..mtrr_mem_type.len())].into(),
        ));

        ranges
    }

    #[test]
    fn test_update_ranges_overlapping() {
        let mut ranges: Vec<MtrrRange> = get_random_mtrr_ranges(50);

        let mut rng = rand::thread_rng();
        let base = rng.gen_range(0..10); // range can begin
        let length = 0xffff_ffff_ffff_fff; // range is big to make it overlap

        let range = MtrrRange::new(base, length, MtrrMemoryType::WriteBack);

        for range in &ranges {
            println!("{}", range);
        }

        println!("-----------------");

        println!("new range: {}", range);

        println!("-----------------");

        update_ranges(&mut ranges, &range);

        let mut lengths = 0;

        for range in ranges {
            println!("{}", range);
            lengths += range.length;
        }

        // we are good if the new ranges add up to the max
        assert_eq!(lengths, MAX);
    }

    #[test]
    fn test_update_ranges_mostly_non_overlapping() {
        let mut ranges: Vec<MtrrRange> = get_random_mtrr_ranges(50);

        let mut rng = rand::thread_rng();
        let base = rng.gen_range(0..MAX - 0xffff); // range can begin anywhere
        let length = 0xffff; // and size is small

        let range = MtrrRange::new(base, length, MtrrMemoryType::WriteBack);

        for range in &ranges {
            println!("{}", range);
        }

        println!("-----------------");

        println!("new range: {}", range);

        println!("-----------------");

        update_ranges(&mut ranges, &range);

        let mut lengths = 0;

        for range in ranges {
            println!("{}", range);
            lengths += range.length;
        }

        // we are good if the new ranges add up to the max
        assert_eq!(lengths, MAX);
    }
}
