use core::mem::size_of;
use core::ptr::write_bytes;

use crate::error::MtrrError;
use crate::error::MtrrResult;
use crate::hal::Hal;
use crate::hal::HalTrait;
use crate::structs::CpuidStructuredExtendedFeatureFlagsEcx;
use crate::structs::CpuidVirPhyAddressSizeEax;
use crate::structs::MsrIa32MtrrDefType;
use crate::structs::MsrIa32TmeActivateRegister;
use crate::structs::MtrrContext;
use crate::structs::MtrrFixedSettings;
use crate::structs::MtrrLibAddress;
use crate::structs::MtrrMemoryCacheType;
use crate::structs::MtrrMemoryRange;
use crate::structs::MtrrSettings;
use crate::structs::MtrrVariableSetting;
use crate::structs::MtrrVariableSettings;
use crate::structs::BIT11;
use crate::structs::BIT7;
use crate::structs::CLEAR_SEED;
use crate::structs::CPUID_EXTENDED_FUNCTION;
use crate::structs::CPUID_SIGNATURE;
use crate::structs::CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS;
use crate::structs::CPUID_VERSION_INFO;
use crate::structs::CPUID_VIR_PHY_ADDRESS_SIZE;
use crate::structs::MMTRR_LIB_FIXED_MTRR_TABLE;
use crate::structs::MMTRR_MEMORY_CACHE_TYPE_SHORT_NAME;
use crate::structs::MSR_IA32_MTRRCAP;
use crate::structs::MSR_IA32_MTRR_DEF_TYPE;
use crate::structs::MSR_IA32_MTRR_PHYSBASE0;
use crate::structs::MSR_IA32_MTRR_PHYSMASK0;
use crate::structs::MSR_IA32_TME_ACTIVATE;
use crate::structs::MTRR_NUMBER_OF_FIXED_MTRR;
use crate::structs::MTRR_NUMBER_OF_LOCAL_MTRR_RANGES;
use crate::structs::MTRR_NUMBER_OF_VARIABLE_MTRR;
use crate::structs::MTRR_NUMBER_OF_WORKING_MTRR_RANGES;
use crate::structs::OR_SEED;
use crate::structs::SCRATCH_BUFFER_SIZE;
use crate::structs::SIZE_1MB;
use crate::utils::get_power_of_two_64;
use crate::utils::high_bit_set_64;
use crate::utils::is_pow2;
use crate::utils::lshift_u64;
use crate::utils::mult_u64x32;
use crate::utils::rshift_u64;

#[cfg(test)]
use crate::structs::VariableMtrr;

fn m(start: u16, index: u16, vertex_count: u16) -> usize {
    (start as usize) * vertex_count as usize + (index as usize)
}

fn o(start: u16, index: u16, vertex_count: u16) -> usize {
    (index as usize) * vertex_count as usize + (start as usize)
}

pub struct MtrrLib<H: HalTrait = Hal> {
    hal: H,
}

impl<H: HalTrait> MtrrLib<H> {
    pub(crate) fn new(hal: H) -> Self {
        Self { hal }
    }

    //
    //  Return whether MTRR is supported.
    //
    //  @param[out]  FixedMtrrSupported   Return whether fixed MTRR is supported.
    //  @param[out]  VariableMtrrRangesCount    Return the max number of variable MTRRs.
    //
    //  @retval TRUE  MTRR is supported when either fixed MTRR is supported or max number
    //                of variable MTRRs is not 0.
    //  @retval FALSE MTRR is not supported when both fixed MTRR is not supported and max
    //                number of variable MTRRs is 0.
    //
    fn mtrr_lib_is_mtrr_supported_internal(&self) -> MtrrResult<(bool, u32)> {
        let edx: u32;

        // Check CPUID(1).EDX[12] for MTRR capability
        edx = self.hal.asm_cpuid(CPUID_VERSION_INFO).edx;

        let mtrr_supported = (edx & (1 << 12)) != 0;

        if !mtrr_supported {
            return Err(MtrrError::MtrrNotSupported);
        }

        // Check the number of variable MTRRs and determine whether fixed MTRRs exist.
        // Check CPUID(1).EDX[12] for MTRR capability
        let mtrr_cap = self.hal.asm_read_msr64(MSR_IA32_MTRRCAP); // MSR_IA32_MTRRCAP
        let vcnt = (mtrr_cap & 0xFF) as u32; // VCNT is in bits [7:0]
        let fix = ((mtrr_cap >> 8) & 0x1) == 1; // FIX is in bit 8

        assert!(vcnt <= MTRR_NUMBER_OF_VARIABLE_MTRR as u32);

        if vcnt == 0 && !fix {
            return Err(MtrrError::MtrrNotSupported);
        }

        Ok((fix, vcnt))
    }

    //
    //  Returns the variable MTRR count for the CPU.
    //
    //  @return Variable MTRR count
    //
    pub(crate) fn get_variable_mtrr_count(&self) -> u32 {
        if !self.is_mtrr_supported() {
            return 0;
        }

        // Read the MSR to get the MTRR capabilities
        let mtrr_cap = self.hal.asm_read_msr64(MSR_IA32_MTRRCAP);

        // Extract the VCNT field from the MSR value
        let vcnt = (mtrr_cap & 0xFF) as u32; // VCNT is in bits [7:0]

        // Ensure VCNT is within valid bounds
        assert!(vcnt <= MTRR_NUMBER_OF_VARIABLE_MTRR as u32);

        vcnt
    }

    //
    //  Returns the default MTRR cache type for the system.
    //
    //  @return  The default MTRR cache type.
    //
    pub fn mtrr_get_default_memory_type(&self) -> MtrrMemoryCacheType {
        if !self.is_mtrr_supported() {
            return MtrrMemoryCacheType::Uncacheable;
        }

        ((self.hal.asm_read_msr64(MSR_IA32_MTRR_DEF_TYPE) & 0xFF) as u8).into()
    }

    //
    //  Preparation before programming MTRR.
    //
    //  This function will do some preparation for programming MTRRs:
    //  disable cache, invalid cache and disable MTRR caching functionality
    //
    //  @param[out] MtrrContext  Pointer to context to save
    //
    fn mtrr_lib_pre_mtrr_change(&mut self, mtrr_context: &mut MtrrContext) {
        let mut def_type: MsrIa32MtrrDefType = Default::default();

        // Disable interrupts and save current interrupt state
        mtrr_context.interrupt_state = self.hal.save_and_disable_interrupts();

        // Enter no fill cache mode, CD=1(Bit30), NW=0 (Bit29)
        self.hal.asm_disable_cache();

        // Save original CR4 value and clear PGE flag (Bit 7)
        mtrr_context.cr4 = self.hal.asm_read_cr4();
        self.hal.asm_write_cr4(mtrr_context.cr4 & !BIT7);

        // Flush all TLBs
        self.hal.cpu_flush_tlb();

        // Save current MTRR default type and disable MTRRs
        mtrr_context.def_type = MsrIa32MtrrDefType::from_bits(self.hal.asm_read_msr64(MSR_IA32_MTRR_DEF_TYPE));
        def_type.set_mem_type(mtrr_context.def_type.mem_type());
        def_type.set_e(false);
        self.hal.asm_write_msr64(MSR_IA32_MTRR_DEF_TYPE, def_type.into_bits());
    }

    //
    //  Cleaning up after programming MTRRs.
    //
    //  This function will do some clean up after programming MTRRs:
    //  Flush all TLBs,  re-enable caching, restore CR4.
    //
    //  @param[in] MtrrContext  Pointer to context to restore
    //
    fn mtrr_lib_post_mtrr_change_enable_cache(&mut self, mtrr_context: &MtrrContext) {
        // Flush all TLBs
        self.hal.cpu_flush_tlb();

        // Enable Normal Mode caching CD=NW=0, CD(Bit30), NW(Bit29)
        self.hal.asm_enable_cache();

        // Restore original CR4 value
        self.hal.asm_write_cr4(mtrr_context.cr4);

        // Restore original interrupt state
        self.hal.set_interrupt_state(mtrr_context.interrupt_state);
    }

    //
    //  Cleaning up after programming MTRRs.
    //
    //  This function will do some clean up after programming MTRRs:
    //  enable MTRR caching functionality, and enable cache
    //
    //  @param[in] MtrrContext  Pointer to context to restore
    //
    fn mtrr_lib_post_mtrr_change(&mut self, mtrr_context: &mut MtrrContext) {
        // Enable Cache MTRR
        // Note: It's possible that MTRR was not enabled earlier.
        //       But it will be enabled here unconditionally.
        mtrr_context.def_type.set_e(true);
        self.hal.asm_write_msr64(MSR_IA32_MTRR_DEF_TYPE, mtrr_context.def_type.into_bits());

        // Call the function to enable cache
        self.mtrr_lib_post_mtrr_change_enable_cache(mtrr_context);
    }

    //
    //  This function gets the content in fixed MTRRs
    //
    //  @param[out]  FixedSettings  A buffer to hold fixed MTRRs content.
    //
    //  @retval The pointer of FixedSettings
    //
    pub(crate) fn mtrr_get_fixed_mtrr(&self) -> MtrrFixedSettings {
        let mut fixed_settings = MtrrFixedSettings::default();

        if !self.is_mtrr_supported() {
            return fixed_settings;
        }

        for (index, entry) in MMTRR_LIB_FIXED_MTRR_TABLE.iter().enumerate() {
            if index < MTRR_NUMBER_OF_FIXED_MTRR {
                fixed_settings.mtrr[index] = self.hal.asm_read_msr64(entry.msr);
            }
        }

        fixed_settings
    }

    //
    //  Worker function will get the raw value in variable MTRRs
    //
    //  If MtrrSetting is not NULL, gets the variable MTRRs raw value from input
    //  MTRR settings buffer.
    //  If MtrrSetting is NULL, gets the variable MTRRs raw value from MTRRs.
    //
    //  @param[in]  MtrrSetting        A buffer holding all MTRRs content.
    //  @param[in]  VariableMtrrRangesCount  Number of variable MTRRs.
    //  @param[out] VariableMtrrSettings   A buffer to hold variable MTRRs content.
    //
    //  @return The VariableMtrrSettings input pointer
    //
    fn mtrr_get_variable_mtrr(&self, variable_mtrr_ranges_count: u32) -> MtrrVariableSettings {
        assert!(variable_mtrr_ranges_count <= MTRR_NUMBER_OF_VARIABLE_MTRR as u32);

        let mut variable_mtrr_settings = MtrrVariableSettings::default();
        for index in 0..variable_mtrr_ranges_count as usize {
            let base_msr = MSR_IA32_MTRR_PHYSBASE0 + (index as u32 * 2);
            let mask_msr = MSR_IA32_MTRR_PHYSMASK0 + (index as u32 * 2);
            variable_mtrr_settings.mtrr[index].base = self.hal.asm_read_msr64(base_msr);
            variable_mtrr_settings.mtrr[index].mask = self.hal.asm_read_msr64(mask_msr);
        }

        variable_mtrr_settings
    }

    //
    //  Programs fixed MTRRs registers.
    //
    //  @param[in]      Type             The memory type to set.
    //  @param[in, out] Base             The base address of memory range.
    //  @param[in, out] Length           The length of memory range.
    //  @param[in, out] LastMsrIndex     On input, the last index of the fixed MTRR MSR to program.
    //                                   On return, the current index of the fixed MTRR MSR to program.
    //  @param[out]     ClearMask        The bits to clear in the fixed MTRR MSR.
    //  @param[out]     OrMask           The bits to set in the fixed MTRR MSR.
    //
    //  @retval RETURN_SUCCESS      The cache type was updated successfully
    //  @retval RETURN_UNSUPPORTED  The requested range or cache type was invalid
    //                              for the fixed MTRRs.
    //
    fn mtrr_lib_program_fixed_mtrr(
        mem_type: u8,
        base: &mut u64,
        length: &mut u64,
        last_msr_index: &mut u32,
        clear_mask: &mut u64,
        or_mask: &mut u64,
    ) -> MtrrResult<()> {
        let mut msr_index: u32 = last_msr_index.wrapping_add(1);
        let left_byte_shift: u32;
        let right_byte_shift: u32;
        let mut sub_length: u64;

        // Find the fixed MTRR index to be programmed
        while msr_index < MMTRR_LIB_FIXED_MTRR_TABLE.len() as u32 {
            let entry = &MMTRR_LIB_FIXED_MTRR_TABLE[msr_index as usize];
            if (*base >= entry.base_address as u64) && (*base < (entry.base_address as u64 + 8 * entry.length as u64)) {
                break;
            }
            msr_index += 1;
        }

        assert!(msr_index != MMTRR_LIB_FIXED_MTRR_TABLE.len() as u32);

        // Find the begin offset in fixed MTRR and calculate byte offset of left shift
        let entry = &MMTRR_LIB_FIXED_MTRR_TABLE[msr_index as usize];
        if ((*base - entry.base_address as u64) % entry.length as u64) != 0 {
            return Err(MtrrError::FixedRangeMtrrBaseAddressNotAligned);
        }

        left_byte_shift = ((*base - entry.base_address as u64) / entry.length as u64) as u32;
        assert!(left_byte_shift < 8);

        // Find the end offset in fixed MTRR and calculate byte offset of right shift
        sub_length = entry.length as u64 * (8 - left_byte_shift) as u64;
        if *length >= sub_length {
            right_byte_shift = 0;
        } else {
            if (*length % entry.length as u64) != 0 {
                return Err(MtrrError::FixedRangeMtrrLengthNotAligned);
            }

            right_byte_shift = 8 - left_byte_shift - (*length / entry.length as u64) as u32;
            sub_length = *length;
        }

        *clear_mask = CLEAR_SEED;
        *or_mask = mult_u64x32(OR_SEED, mem_type as u32);

        if left_byte_shift != 0 {
            *clear_mask &= lshift_u64(*clear_mask, left_byte_shift * 8);
            *or_mask &= lshift_u64(*or_mask, left_byte_shift * 8);
        }

        if right_byte_shift != 0 {
            *clear_mask &= rshift_u64(*clear_mask, right_byte_shift * 8);
            *or_mask &= rshift_u64(*or_mask, right_byte_shift * 8);
        }

        *length -= sub_length;
        *base += sub_length;

        *last_msr_index = msr_index;

        Ok(())
    }

    //
    //  Convert variable MTRRs to a RAW MTRR_MEMORY_RANGE array.
    //  One MTRR_MEMORY_RANGE element is created for each MTRR setting.
    //  The routine doesn't remove the overlap or combine the near-by region.
    //
    //  @param[in]   VariableMtrrSettings      The variable MTRR values to shadow
    //  @param[in]   VariableMtrrRangesCount     The number of variable MTRRs
    //  @param[in]   MtrrValidBitsMask     The mask for the valid bit of the MTRR
    //  @param[in]   MtrrValidAddressMask  The valid address mask for MTRR
    //  @param[out]  VariableMtrrRanges          The array to shadow variable MTRRs content
    //
    //  @return      Number of MTRRs which has been used.
    //
    fn mtrr_lib_get_variable_memory_ranges(
        variable_mtrr_settings: &MtrrVariableSettings,
        variable_mtrr_ranges_count: usize,
        mtrr_valid_bits_mask: u64,
        mtrr_valid_address_mask: u64,
        variable_mtrr_ranges: &mut [MtrrMemoryRange],
    ) -> u32 {
        let mut used_mtrr = 0;

        for index in 0..variable_mtrr_ranges_count {
            let entry = &variable_mtrr_settings.mtrr[index];
            let mask = entry.mask;
            let base = entry.base;

            // Check if the MTRR is valid
            if (mask >> 11) & 1 != 0 {
                variable_mtrr_ranges[index].base_address = base & mtrr_valid_address_mask;
                variable_mtrr_ranges[index].length = ((!(mask & mtrr_valid_address_mask)) & mtrr_valid_bits_mask) + 1;
                variable_mtrr_ranges[index].mem_type = MtrrMemoryCacheType::from((base & 0x0ff) as u8).into();
                used_mtrr += 1;
            }
        }

        used_mtrr
    }

    //
    //  Return the biggest alignment (lowest set bit) of address.
    //  The function is equivalent to: 1 << LowBitSet64 (Address).
    //
    //  @param Address    The address to return the alignment.
    //  @param Alignment0 The alignment to return when Address is 0.
    //
    //  @return The least alignment of the Address.
    //
    fn mtrr_lib_biggest_alignment(address: u64, alignment0: u64) -> u64 {
        if address == 0 {
            alignment0
        } else {
            address & ((!address) + 1)
        }
    }

    //
    //  Return whether the left MTRR type precedes the right MTRR type.
    //
    //  The MTRR type precedence rules are:
    //    1. UC precedes any other type
    //    2. WT precedes WB
    //  For further details, please refer the IA32 Software Developer's Manual,
    //  Volume 3, Section "MTRR Precedences".
    //
    //  @param Left  The left MTRR type.
    //  @param Right The right MTRR type.
    //
    //  @retval TRUE  Left precedes Right.
    //  @retval FALSE Left doesn't precede Right.
    //
    fn mtrr_lib_type_left_precede_right(left: MtrrMemoryCacheType, right: MtrrMemoryCacheType) -> bool {
        left == MtrrMemoryCacheType::Uncacheable
            || (left == MtrrMemoryCacheType::WriteThrough && right == MtrrMemoryCacheType::WriteBack)
    }

    //
    //  Initializes the valid bits mask and valid address mask for MTRRs.
    //
    //  This function initializes the valid bits mask and valid address mask for MTRRs.
    //
    //  @param[out]  MtrrValidBitsMask     The mask for the valid bit of the MTRR
    //  @param[out]  MtrrValidAddressMask  The valid address mask for the MTRR
    //
    fn mtrr_lib_initialize_mtrr_mask(&self) -> (u64, u64) {
        let mtrr_valid_bits_mask;
        let mtrr_valid_address_mask;

        let mut vir_phy_address_size = CpuidVirPhyAddressSizeEax::default();

        // Get maximum CPUID function number
        let max_extended_function = self.hal.asm_cpuid(CPUID_EXTENDED_FUNCTION).eax;

        // Check if CPUID_VIR_PHY_ADDRESS_SIZE is supported
        if max_extended_function >= CPUID_VIR_PHY_ADDRESS_SIZE {
            let vir_phy_address_size_u32 = self.hal.asm_cpuid(CPUID_VIR_PHY_ADDRESS_SIZE).eax;
            vir_phy_address_size = CpuidVirPhyAddressSizeEax::from_bits(vir_phy_address_size_u32);
        } else {
            vir_phy_address_size.set_physical_address_bits(36);
        }

        // CPUID enumeration of MAX_PA is unaffected by TME-MK activation and will continue
        // to report the maximum physical address bits available for software to use,
        // irrespective of the number of KeyID bits.
        // So, we need to check if TME is enabled and adjust the PA size accordingly.
        let max_function = self.hal.asm_cpuid(CPUID_SIGNATURE).eax;
        if max_function >= CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS {
            let extended_feature_flags_ecx_u32 = self.hal.asm_cpuid_ex(CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS, 0).ecx;

            let extended_feature_flags_ecx =
                CpuidStructuredExtendedFeatureFlagsEcx::from_bits(extended_feature_flags_ecx_u32);

            if extended_feature_flags_ecx.tme_en() {
                let tme_activate =
                    MsrIa32TmeActivateRegister::from_bits(self.hal.asm_read_msr64(MSR_IA32_TME_ACTIVATE));
                if tme_activate.tme_enable() {
                    vir_phy_address_size.set_physical_address_bits(
                        vir_phy_address_size.physical_address_bits() - tme_activate.mk_tme_keyid_bits(),
                    );
                }
            }
        }

        mtrr_valid_bits_mask = (1u64 << vir_phy_address_size.physical_address_bits()) - 1;
        mtrr_valid_address_mask = mtrr_valid_bits_mask & 0xfffffffffffff000u64;

        (mtrr_valid_bits_mask, mtrr_valid_address_mask)
    }

    //
    //  Determines the real attribute of a memory range.
    //
    //  This function is to arbitrate the real attribute of the memory when
    //  there are 2 MTRRs covers the same memory range. For further details,
    //  please refer the IA32 Software Developer's Manual, Volume 3,
    //  Section "MTRR Precedences".
    //
    //  @param[in]  MtrrType1    The first kind of Memory type
    //  @param[in]  MtrrType2    The second kind of memory type
    //
    fn mtrr_lib_precedence(
        &self,
        mtrr_type1: MtrrMemoryCacheType,
        mtrr_type2: MtrrMemoryCacheType,
    ) -> MtrrMemoryCacheType {
        if mtrr_type1 == mtrr_type2 {
            return mtrr_type1;
        }

        assert!(
            Self::mtrr_lib_type_left_precede_right(mtrr_type1, mtrr_type2)
                || Self::mtrr_lib_type_left_precede_right(mtrr_type2, mtrr_type1)
        );

        if Self::mtrr_lib_type_left_precede_right(mtrr_type1, mtrr_type2) {
            mtrr_type1
        } else {
            mtrr_type2
        }
    }

    //
    //  Worker function will get the memory cache type of the specific address.
    //
    //  If MtrrSetting is not NULL, gets the memory cache type from input
    //  MTRR settings buffer.
    //  If MtrrSetting is NULL, gets the memory cache type from MTRRs.
    //
    //  @param[in]  MtrrSetting        A buffer holding all MTRRs content.
    //  @param[in]  Address            The specific address
    //
    //  @return Memory cache type of the specific address
    //
    fn mtrr_get_memory_attribute_by_address_worker(&self, address: u64) -> MtrrMemoryCacheType {
        let def_type = MsrIa32MtrrDefType::from(self.hal.asm_read_msr64(MSR_IA32_MTRR_DEF_TYPE));

        if !def_type.e() {
            return MtrrMemoryCacheType::Uncacheable;
        }

        // If address is less than 1M, then try to go through the fixed MTRR
        if address < SIZE_1MB as u64 {
            if def_type.fe() {
                for index in 0..MTRR_NUMBER_OF_FIXED_MTRR {
                    if (address >= MMTRR_LIB_FIXED_MTRR_TABLE[index].base_address as u64)
                        && (address
                            < MMTRR_LIB_FIXED_MTRR_TABLE[index].base_address as u64
                                + (MMTRR_LIB_FIXED_MTRR_TABLE[index].length as u64 * 8))
                    {
                        let sub_index = (address - MMTRR_LIB_FIXED_MTRR_TABLE[index].base_address as u64)
                            / MMTRR_LIB_FIXED_MTRR_TABLE[index].length as u64;
                        let fixed_mtrr = self.hal.asm_read_msr64(MMTRR_LIB_FIXED_MTRR_TABLE[index].msr);
                        return (((fixed_mtrr >> (sub_index * 8)) & 0xFF) as u8).into();
                    }
                }
            }
        }

        let variable_mtrr_ranges_count = self.get_variable_mtrr_count();
        assert!(variable_mtrr_ranges_count <= MTRR_NUMBER_OF_VARIABLE_MTRR as u32);

        let variable_mtrr_settings = self.mtrr_get_variable_mtrr(variable_mtrr_ranges_count);
        let (mtrr_valid_bits_mask, mtrr_valid_address_mask) = self.mtrr_lib_initialize_mtrr_mask();
        let mut variable_mtrr_ranges: [MtrrMemoryRange; MTRR_NUMBER_OF_VARIABLE_MTRR] = Default::default();
        let _ = Self::mtrr_lib_get_variable_memory_ranges(
            &variable_mtrr_settings,
            variable_mtrr_ranges_count as usize,
            mtrr_valid_bits_mask,
            mtrr_valid_address_mask,
            &mut variable_mtrr_ranges,
        );

        // Go through the variable MTRR
        let mut mem_type = MtrrMemoryCacheType::Invalid;
        for range in variable_mtrr_ranges.iter() {
            if range.length != 0 {
                if (address >= range.base_address) && (address < range.base_address + range.length) {
                    if mem_type == MtrrMemoryCacheType::Invalid {
                        mem_type = range.mem_type;
                    } else {
                        mem_type = self.mtrr_lib_precedence(mem_type, range.mem_type);
                    }
                }
            }
        }

        // If there is no MTRR which covers the Address, use the default MTRR type.
        if mem_type == MtrrMemoryCacheType::Invalid {
            mem_type = def_type.mem_type().into();
        }

        mem_type
    }

    //
    //  This function will get the memory cache type of the specific address.
    //
    //  This function is mainly for debug purpose.
    //
    //  @param[in]  Address   The specific address
    //
    //  @return Memory cache type of the specific address
    //
    pub fn mtrr_get_memory_attribute(&self, address: u64) -> MtrrMemoryCacheType {
        if !self.is_mtrr_supported() {
            return MtrrMemoryCacheType::Uncacheable;
        }

        self.mtrr_get_memory_attribute_by_address_worker(address)
    }

    //
    //  Update the Ranges array to change the specified range identified by
    //  BaseAddress and Length to Type.
    //
    //  @param Ranges      Array holding memory type settings for all memory regions.
    //  @param Capacity    The maximum count of memory ranges the array can hold.
    //  @param Count       Return the new memory range count in the array.
    //  @param BaseAddress The base address of the memory range to change type.
    //  @param Length      The length of the memory range to change type.
    //  @param Type        The new type of the specified memory range.
    //
    //  @retval RETURN_SUCCESS          The type of the specified memory range is
    //                                  changed successfully.
    //  @retval RETURN_ALREADY_STARTED  The type of the specified memory range equals
    //                                  to the desired type.
    //  @retval RETURN_OUT_OF_RESOURCES The new type set causes the count of memory
    //                                  range exceeds capacity.
    //
    fn mtrr_lib_set_memory_type(
        &self,
        working_ranges: &mut [MtrrMemoryRange],
        working_ranges_capacity: usize,
        working_ranges_count: &mut usize,
        mut base_address: u64,
        mut length: u64,
        mem_type: MtrrMemoryCacheType,
    ) -> MtrrResult<()> {
        assert!(length != 0);

        let mut length_left = 0;
        let mut length_right = 0;
        let limit = base_address + length;
        let mut start_index = *working_ranges_count;
        let mut end_index = *working_ranges_count;

        // println!("Assinged start_index: {} end_index: {} working_ranges_count: {}", start_index, end_index, *working_ranges_count);

        // Determine which existing range can accommodate the new range
        for index in 0..*working_ranges_count {
            let range = &working_ranges[index];

            // println!("index: {} base_address/limit: {:x}/{:x} range base_address: {:x} length: {:x} mem_type: {:?}",
            // index, base_address, limit, range.base_address, range.length, range.mem_type);
            // start index can begin on one slot and end index could land on another
            // slot depending up on the size of the new range
            if start_index == *working_ranges_count
                && range.base_address <= base_address
                && base_address < range.base_address + range.length
            {
                start_index = index;
                length_left = base_address - range.base_address;
            }

            if end_index == *working_ranges_count
                && range.base_address < limit
                && limit <= range.base_address + range.length
            {
                end_index = index;
                length_right = range.base_address + range.length - limit;
                break;
            }
        }

        // println!("modified start_index: {} end_index: {} working_ranges_count: {}", start_index, end_index, *working_ranges_count);
        assert!(start_index != *working_ranges_count && end_index != *working_ranges_count);
        if start_index == end_index && working_ranges[start_index].mem_type == mem_type {
            return Err(MtrrError::ReturnAlreadyStarted);
        }

        // The type change may cause merging with previous range or next range.
        // Update the StartIndex, EndIndex, BaseAddress, Length so that following
        // logic doesn't need to consider merging.
        if start_index != 0 {
            if length_left == 0 && working_ranges[start_index - 1].mem_type == mem_type {
                start_index -= 1;
                length += working_ranges[start_index].length;
                base_address -= working_ranges[start_index].length;
            }
        }

        if end_index != *working_ranges_count - 1 {
            if length_right == 0 && working_ranges[end_index + 1].mem_type == mem_type {
                end_index += 1;
                length += working_ranges[end_index].length;
            }
        }

        // println!("start_index: {} end_index: {}", start_index, end_index);
        let mut delta_count: i64 = end_index as i64 - start_index as i64 - 2;

        if length_left == 0 {
            delta_count += 1;
        }
        if length_right == 0 {
            delta_count += 1;
        }

        if *working_ranges_count as i64 - delta_count > working_ranges_capacity as i64 {
            return Err(MtrrError::ReturnOutOfResources);
        }

        // Reserve space for the new ranges
        for i in (0..(*working_ranges_count - end_index - 1)).rev() {
            let src = i + end_index + 1;
            let dest = (i as i64 + end_index as i64 + 1 - delta_count) as usize;
            working_ranges[dest] = working_ranges[src].clone();

            // println!("src: {} dest: {} working_ranges_count: {}", src, dest, *working_ranges_count);
        }

        *working_ranges_count = (*working_ranges_count as i64 - delta_count) as i64 as usize;
        // println!("working_ranges_count: {} delta_count: {}", *working_ranges_count, delta_count);
        if length_left != 0 {
            working_ranges[start_index].length = length_left;
            start_index += 1;
        }

        if length_right != 0 {
            working_ranges[(end_index as i64 - delta_count) as usize].base_address = base_address + length;
            working_ranges[(end_index as i64 - delta_count) as usize].length = length_right;
            working_ranges[(end_index as i64 - delta_count) as usize].mem_type = working_ranges[end_index].mem_type;
        }

        working_ranges[start_index].base_address = base_address;
        working_ranges[start_index].length = length;
        working_ranges[start_index].mem_type = mem_type;

        Ok(())
    }

    //
    //  Return the number of memory types in range [BaseAddress, BaseAddress + Length).
    //
    //  @param Ranges      Array holding memory type settings for all memory regions.
    //  @param RangeCount  The count of memory ranges the array holds.
    //  @param BaseAddress Base address.
    //  @param Length      Length.
    //  @param Types       Return bit mask to indicate all memory types in the specified range.
    //
    //  @retval  Number of memory types.
    //
    fn mtrr_lib_get_number_of_types(
        &self,
        ranges: &[MtrrMemoryRange],
        range_count: usize,
        mut base_address: u64,
        mut length: u64,
        types: Option<&mut u8>,
    ) -> u8 {
        let mut type_count = 0;
        let mut local_types: u8 = 0;

        for index in 0..range_count {
            let range = &ranges[index];

            if range.base_address <= base_address && base_address < range.base_address + range.length {
                if local_types & (1 << range.mem_type as u8) == 0 {
                    local_types |= 1 << range.mem_type as u8;
                    type_count += 1;
                }

                if base_address + length > range.base_address + range.length {
                    length -= range.base_address + range.length - base_address;
                    base_address = range.base_address + range.length;
                } else {
                    break;
                }
            }
        }

        if let Some(types_ref) = types {
            *types_ref = local_types;
        }

        type_count
    }

    //
    //  Calculate the least MTRR number from vertex Start to Stop and update
    //  the Previous of all vertices from Start to Stop is updated to reflect
    //  how the memory range is covered by MTRR.
    //
    //  @param VertexCount     The count of vertices in the graph.
    //  @param Vertices        Array holding all vertices.
    //  @param Weight          2-dimention array holding weights between vertices.
    //  @param Start           Start vertex.
    //  @param Stop            Stop vertex.
    //  @param IncludeOptional TRUE to count the optional weight.
    //
    fn mtrr_lib_calculate_least_mtrrs(
        &self,
        vertex_count: u16,
        vertices: &mut [MtrrLibAddress], // Array of vertices
        weight: &[u8],                   // Array of weights
        start: u16,
        stop: u16,
        include_optional: bool,
    ) {
        let mut min_weight: u8;
        let mut min_i: u16;
        let mut mandatory: u8;
        let mut optional: u8;

        const MAX_WEIGHT: u8 = 0xFF;

        // Initialize vertices and weights
        for index in start..=stop {
            vertices[index as usize].visited = false;
            mandatory = weight[m(start, index, vertex_count)];
            vertices[index as usize].weight = mandatory;
            if mandatory != MAX_WEIGHT {
                optional = if include_optional { weight[o(start, index, vertex_count)] } else { 0 };
                vertices[index as usize].weight += optional;
                assert!(vertices[index as usize].weight >= optional);
            }
        }

        min_i = start;
        min_weight = 0;

        while !vertices[stop as usize].visited {
            // Update the weight from the shortest vertex to other unvisited vertices
            for index in (start + 1)..=stop {
                if !vertices[index as usize].visited {
                    mandatory = weight[m(min_i, index, vertex_count)];
                    if mandatory != MAX_WEIGHT {
                        optional = if include_optional { weight[o(min_i, index, vertex_count)] } else { 0 };
                        if min_weight as u32 + mandatory as u32 + optional as u32
                            <= vertices[index as usize].weight as u32
                        {
                            vertices[index as usize].weight = min_weight + mandatory + optional;
                            vertices[index as usize].previous = min_i; // Previous is start-based
                        }
                    }
                }
            }

            // Find the shortest vertex from Start
            min_i = vertex_count;
            min_weight = MAX_WEIGHT;
            for index in (start + 1)..=stop {
                if !vertices[index as usize].visited && min_weight > vertices[index as usize].weight {
                    min_i = index;
                    min_weight = vertices[index as usize].weight;
                }
            }

            // Mark the shortest vertex from Start as visited
            vertices[min_i as usize].visited = true;
        }
    }

    //
    //  Append the MTRR setting to MTRR setting array.
    //
    //  @param Mtrrs        Array holding all MTRR settings.
    //  @param MtrrCapacity Capacity of the MTRR array.
    //  @param MtrrCount    The count of MTRR settings in array.
    //  @param BaseAddress  Base address.
    //  @param Length       Length.
    //  @param Type         Memory type.
    //
    //  @retval RETURN_SUCCESS          MTRR setting is appended to array.
    //  @retval RETURN_OUT_OF_RESOURCES Array is full.
    //
    fn mtrr_lib_append_variable_mtrr(
        &self,
        mtrrs: &mut [MtrrMemoryRange],
        mtrr_capacity: usize,
        mtrr_count: &mut usize,
        base_address: u64,
        length: u64,
        mem_type: MtrrMemoryCacheType,
    ) -> MtrrResult<()> {
        if *mtrr_count == mtrr_capacity {
            return Err(MtrrError::VariableRangeMtrrExhausted);
        }

        mtrrs[*mtrr_count].base_address = base_address;
        mtrrs[*mtrr_count].length = length;
        mtrrs[*mtrr_count].mem_type = mem_type;
        *mtrr_count += 1;

        Ok(())
    }

    //
    //  Return the memory type that has the least precedence.
    //
    //  @param TypeBits  Bit mask of memory type.
    //
    //  @retval  Memory type that has the least precedence.
    //
    fn mtrr_lib_lowest_type(mem_type_bits: u8) -> MtrrMemoryCacheType {
        assert!(mem_type_bits != 0);
        let mut mem_type = 7u8;
        let mut mem_type_bits = mem_type_bits as i8;
        while mem_type_bits > 0 {
            mem_type -= 1;
            mem_type_bits <<= 1;
        }

        mem_type.into()
    }

    //
    //  Calculate the subtractive path from vertex Start to Stop.
    //
    //  @param DefaultType  Default memory type.
    //  @param A0           Alignment to use when base address is 0.
    //  @param Ranges       Array holding memory type settings for all memory regions.
    //  @param RangeCount   The count of memory ranges the array holds.
    //  @param VertexCount  The count of vertices in the graph.
    //  @param Vertices     Array holding all vertices.
    //  @param Weight       2-dimention array holding weights between vertices.
    //  @param Start        Start vertex.
    //  @param Stop         Stop vertex.
    //  @param Types        Type bit mask of memory range from Start to Stop.
    //  @param TypeCount    Number of different memory types from Start to Stop.
    //  @param Mtrrs        Array holding all MTRR settings.
    //  @param MtrrCapacity Capacity of the MTRR array.
    //  @param MtrrCount    The count of MTRR settings in array.
    //
    //  @retval RETURN_SUCCESS          The subtractive path is calculated successfully.
    //  @retval RETURN_OUT_OF_RESOURCES The MTRR setting array is full.
    //
    fn mtrr_lib_calculate_subtractive_path(
        &self,
        default_type: MtrrMemoryCacheType,
        a0: u64,
        ranges: &[MtrrMemoryRange],
        range_count: usize,
        vertex_count: u16,
        vertices: &mut [MtrrLibAddress],
        weight: &mut [u8],
        start: u16,
        stop: u16,
        types: u8,
        type_count: u8,
        mtrrs: Option<&mut [MtrrMemoryRange]>,
        mtrr_capacity: Option<usize>,
        mtrr_count: Option<&mut usize>,
    ) -> MtrrResult<()> {
        const MAX_UINT64: u64 = 0xFFFFFFFFFFFFFFFFu64;

        let mut base = vertices[start as usize].address;
        let mut length = vertices[stop as usize].address - base;
        let lowest_type = Self::mtrr_lib_lowest_type(types);
        // Clear the lowest type (highest bit) to get the precedent types
        let precedent_types = !(1 << (lowest_type as u8)) & types;
        let lowest_precedent_type = Self::mtrr_lib_lowest_type(precedent_types);

        if mtrrs.is_none() {
            weight[m(start, stop, vertex_count)] = if lowest_type == default_type { 0 } else { 1 };
            weight[o(start, stop, vertex_count)] = if lowest_type == default_type { 1 } else { 0 };
        }

        // Add all high level ranges
        let mut hbase = MAX_UINT64;
        let mut hlength = 0u64;

        let mut mtrrs_unwrap = &mut [MtrrMemoryRange::default()][..];
        let mut mtrr_count_unwrap = &mut 0;
        let mtrrs_is_none = mtrrs.is_none();
        if !mtrrs_is_none {
            mtrrs_unwrap = mtrrs.unwrap();
            mtrr_count_unwrap = mtrr_count.unwrap();
        }

        for index in 0..range_count {
            if length == 0 {
                break;
            }

            if base < ranges[index].base_address || ranges[index].base_address + ranges[index].length <= base {
                continue;
            }

            // Base is in the Range[Index]
            let sub_length = if base + length > ranges[index].base_address + ranges[index].length {
                ranges[index].base_address + ranges[index].length - base
            } else {
                length
            };

            if (1 << (ranges[index].mem_type as u8)) & precedent_types != 0 {
                // Meet a range whose types take precedence.
                // Update the [HBase, HBase + HLength) to include the range,
                // [HBase, HBase + HLength) may contain sub ranges with 2 different types, and both take precedence.
                if hbase == MAX_UINT64 {
                    hbase = base;
                }
                hlength += sub_length;
            }

            base += sub_length;
            length -= sub_length;

            if hlength == 0 {
                continue;
            }

            if ranges[index].mem_type == lowest_type || length == 0 {
                // meet low type or end

                // Add the MTRRs for each high priority type range
                // the range[HBase, HBase + HLength) contains only two types.
                // We might use positive or subtractive, depending on which way uses less MTRR
                let mut sub_start = start;
                while sub_start <= stop {
                    if vertices[sub_start as usize].address == hbase {
                        break;
                    }
                    sub_start += 1;
                }

                let mut sub_stop = start;
                while sub_stop <= stop {
                    if vertices[sub_stop as usize].address == hbase + hlength {
                        break;
                    }
                    sub_stop += 1;
                }

                assert_eq!(vertices[sub_start as usize].address, hbase);
                assert_eq!(vertices[sub_stop as usize].address, hbase + hlength);

                if type_count == 2 || sub_start == sub_stop - 1 {
                    // add subtractive MTRRs for [HBase, HBase + HLength)
                    // [HBase, HBase + HLength) contains only one type.
                    // while - loop is to split the range to MTRR - compliant aligned range.

                    if mtrrs_is_none {
                        weight[m(start, stop, vertex_count)] += (sub_stop - sub_start) as u8;
                    } else {
                        while sub_start != sub_stop {
                            let status = self.mtrr_lib_append_variable_mtrr(
                                mtrrs_unwrap,
                                mtrr_capacity.unwrap() as usize,
                                mtrr_count_unwrap,
                                vertices[sub_start as usize].address,
                                vertices[sub_start as usize].length,
                                vertices[sub_start as usize].mem_type.into(),
                            );
                            if status.is_err() {
                                return status;
                            }
                            sub_start += 1;
                        }
                    }
                } else {
                    assert_eq!(type_count, 3);
                    self.mtrr_lib_calculate_least_mtrrs(vertex_count, vertices, weight, sub_start, sub_stop, true);

                    if mtrrs_is_none {
                        weight[m(start, stop, vertex_count)] += vertices[sub_stop as usize].weight;
                    } else {
                        // When we need to collect the optimal path from SubStart to SubStop
                        while sub_stop != sub_start {
                            let cur = sub_stop;
                            let pre = vertices[cur as usize].previous;
                            sub_stop = pre;

                            if weight[m(pre, cur, vertex_count)] + weight[o(pre, cur, vertex_count)] != 0 {
                                let status = self.mtrr_lib_append_variable_mtrr(
                                    mtrrs_unwrap,
                                    mtrr_capacity.unwrap(),
                                    mtrr_count_unwrap,
                                    vertices[pre as usize].address,
                                    vertices[cur as usize].address - vertices[pre as usize].address,
                                    if pre != cur - 1 {
                                        lowest_precedent_type
                                    } else {
                                        vertices[pre as usize].mem_type.into()
                                    },
                                );
                                if status.is_err() {
                                    return status;
                                }
                            }

                            if pre != cur - 1 {
                                let status = self.mtrr_lib_calculate_subtractive_path(
                                    default_type,
                                    a0,
                                    ranges,
                                    range_count,
                                    vertex_count,
                                    vertices,
                                    weight,
                                    pre,
                                    cur,
                                    precedent_types,
                                    2,
                                    Some(mtrrs_unwrap),
                                    mtrr_capacity,
                                    Some(mtrr_count_unwrap),
                                );
                                if status.is_err() {
                                    return status;
                                }
                            }
                        }
                    }
                }

                // Reset HBase, HLength
                hbase = MAX_UINT64;
                hlength = 0;
            }
        }

        Ok(())
    }

    //
    //  Calculate MTRR settings to cover the specified memory ranges.
    //
    //  @param DefaultType  Default memory type.
    //  @param A0           Alignment to use when base address is 0.
    //  @param Ranges       Memory range array holding the memory type
    //                      settings for all memory address.
    //  @param RangeCount   Count of memory ranges.
    //  @param Scratch      A temporary scratch buffer that is used to perform the calculation.
    //                      This is an optional parameter that may be NULL.
    //  @param ScratchSize  Pointer to the size in bytes of the scratch buffer.
    //                      It may be updated to the actual required size when the calculation
    //                      needs more scratch buffer.
    //  @param Mtrrs        Array holding all MTRR settings.
    //  @param MtrrCapacity Capacity of the MTRR array.
    //  @param MtrrCount    The count of MTRR settings in array.
    //
    //  @retval RETURN_SUCCESS          Variable MTRRs are allocated successfully.
    //  @retval RETURN_OUT_OF_RESOURCES Count of variable MTRRs exceeds capacity.
    //  @retval RETURN_BUFFER_TOO_SMALL The scratch buffer is too small for MTRR calculation.
    //
    fn mtrr_lib_calculate_mtrrs(
        &self,
        default_type: MtrrMemoryCacheType,
        a0: u64,
        ranges: &[MtrrMemoryRange],
        range_count: usize,
        scratch: &mut [u8],
        scratch_size: &mut usize,
        mtrrs: &mut [MtrrMemoryRange],
        mtrr_capacity: usize,
        mtrr_count: &mut usize,
    ) -> MtrrResult<()> {
        const MAX_WEIGHT: u8 = 0xFF;
        const MAX_UINT8: u8 = 0xFF;

        let base0 = ranges[0].base_address;
        let base1 = ranges[range_count - 1].base_address + ranges[range_count - 1].length;

        println!(
            "MtrrLibCalculateMtrrs - default_type: {:?} a0: {:x} range_count: {:x}",
            default_type, a0, range_count
        );
        for (index, range) in ranges.iter().enumerate() {
            println!(
                "range[{}]  base_address: {:x} - {:x} mem_type: {:?}",
                index,
                range.base_address,
                range.base_address + range.length,
                range.mem_type
            );
        }
        assert!(base0 & !((base1 - base0) - 1) == base0);

        // Counting the number of vertices
        let mut vertices: &mut [MtrrLibAddress] = unsafe {
            core::slice::from_raw_parts_mut(
                scratch.as_mut_ptr() as *mut MtrrLibAddress,
                scratch.len() / size_of::<MtrrLibAddress>(),
            )
        };
        let mut vertex_index = 0;

        for index in 0..range_count {
            let mut base = ranges[index].base_address;
            let mut length = ranges[index].length;

            while length != 0 {
                let alignment = Self::mtrr_lib_biggest_alignment(base, a0);
                let mut sub_length = alignment;
                // println!(
                //     "  Vertex[{}] = {:x} - {:x}  alignment: {:x} sublength: {:x} length: {:x}",
                //     vertex_index,
                //     base,
                //     base + sub_length,
                //     alignment,
                //     sub_length,
                //     length
                // );
                if sub_length > length {
                    sub_length = get_power_of_two_64(length);
                }

                // println!(
                //     "       Vertex[{}] = {:x} - {:x}  alignment: {:x} sublength: {:x} length: {:x}",
                //     vertex_index,
                //     base,
                //     base + sub_length,
                //     alignment,
                //     sub_length,
                //     length
                // );
                if vertex_index < *scratch_size / size_of::<MtrrLibAddress>() {
                    vertices[vertex_index] = MtrrLibAddress {
                        address: base,
                        alignment,
                        mem_type: ranges[index].mem_type as u8,
                        length: sub_length,
                        previous: 0,
                        weight: 0,
                        visited: false,
                    };
                }

                base += sub_length;
                length -= sub_length;
                vertex_index += 1;
                // println!(
                //     "  Vertex[{}] = {:x} - {:x}  alignment: {:x} sublength: {:x} mem_type: {:x}",
                //     vertex_index - 1,
                //     vertices[vertex_index - 1].address,
                //     vertices[vertex_index - 1].address + vertices[vertex_index - 1].length,
                //     alignment,
                //     sub_length,
                //     vertices[vertex_index - 1].mem_type
                // );
            }
        }

        // Vertices[VertexIndex] = Base1, so whole vertex count is (VertexIndex + 1).
        let vertex_count = vertex_index + 1;
        println!(
            "  Count of vertices ({:x} - {:x}) = {}\n",
            ranges[0].base_address,
            ranges[range_count - 1].base_address + ranges[range_count - 1].length,
            vertex_count
        );

        assert!(vertex_count < u16::MAX as usize);

        let required_scratch_size =
            vertex_count * core::mem::size_of::<MtrrLibAddress>() + vertex_count * vertex_count + 1;
        if *scratch_size < required_scratch_size {
            *scratch_size = required_scratch_size;
            return Err(MtrrError::ReturnBufferTooSmall);
        }

        vertices[vertex_count - 1].address = base1;

        let weight: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(
                vertices.as_mut_ptr().offset(vertex_count as isize) as *mut u8,
                vertex_count * vertex_count + 1,
            )
        };

        for vertex_index in 0..vertex_count {
            unsafe {
                // println!("vertex_index: {}", vertex_index);
                // Set optional weight between vertices and self->self to 0
                let mm = m(vertex_index as u16, 0, vertex_count as u16);
                // println!("mm: {}", mm);
                write_bytes(&mut weight[mm] as *mut u8, 0, vertex_index + 1);
                // Set mandatory weight between vertices to MAX_WEIGHT
                let mm2 = m(vertex_index as u16, vertex_index as u16 + 1, vertex_count as u16);
                // println!("mm2: {}", mm2);
                write_bytes(&mut weight[mm2] as *mut u8, MAX_WEIGHT, vertex_count - vertex_index - 1);
            }
        }

        // Set mandatory weight and optional weight for adjacent vertices
        for vertex_index in 0..vertex_count - 1 {
            if vertices[vertex_index].mem_type != default_type as u8 {
                weight[m(vertex_index as u16, vertex_index as u16 + 1, vertex_count as u16)] = 1;
                weight[o(vertex_index as u16, vertex_index as u16 + 1, vertex_count as u16)] = 0;
            } else {
                weight[m(vertex_index as u16, vertex_index as u16 + 1, vertex_count as u16)] = 0;
                weight[o(vertex_index as u16, vertex_index as u16 + 1, vertex_count as u16)] = 1;
            }
        }

        for type_count in 2..=3 {
            for start in 0..(vertex_count as u32) {
                for stop in (start + 2)..(vertex_count as u32) {
                    assert!(vertices[stop as usize].address > vertices[start as usize].address);

                    let length = vertices[stop as usize].address - vertices[start as usize].address;

                    if length > vertices[start as usize].alignment {
                        // Pickup a new start when [Start, Stop) cannot be described by one MTRR.
                        break;
                    }

                    if weight[m(start as u16, stop as u16, vertex_count as u16)] == MAX_WEIGHT && is_pow2(length) {
                        let mut type_out = 0;

                        if self.mtrr_lib_get_number_of_types(
                            ranges,
                            range_count,
                            vertices[start as usize].address,
                            vertices[stop as usize].address - vertices[start as usize].address,
                            Some(&mut type_out),
                        ) == type_count
                        {
                            // Update the Weight[Start, Stop] using subtractive path.
                            let _ = self.mtrr_lib_calculate_subtractive_path(
                                default_type,
                                a0,
                                ranges,
                                range_count,
                                vertex_count as u16,
                                vertices,
                                weight,
                                start as u16,
                                stop as u16,
                                type_out,
                                type_count,
                                None,
                                None,
                                None,
                            );
                        } else if type_count == 2 {
                            // Pick up a new start when we expect 2-type range, but 3-type range is met.
                            // Because no matter how Stop is increased, we always meet 3-type range.
                            break;
                        }
                    }
                }
            }
        }

        self.mtrr_lib_calculate_least_mtrrs(
            vertex_count as u16,
            &mut vertices,
            weight,
            0,
            vertex_count as u16 - 1,
            false,
        );
        let mut stop = vertex_count as u16 - 1;

        while stop != 0 {
            let start = vertices[stop as usize].previous;
            let mut type_count = MAX_UINT8;
            let mut mem_type = 0;

            if weight[m(start, stop, vertex_count as u16)] != 0 {
                type_count = self.mtrr_lib_get_number_of_types(
                    ranges,
                    range_count,
                    vertices[start as usize].address,
                    vertices[stop as usize].address - vertices[start as usize].address,
                    Some(&mut mem_type),
                );
                let status = self.mtrr_lib_append_variable_mtrr(
                    mtrrs,
                    mtrr_capacity,
                    mtrr_count,
                    vertices[start as usize].address,
                    vertices[stop as usize].address - vertices[start as usize].address,
                    Self::mtrr_lib_lowest_type(mem_type),
                );
                if status.is_err() {
                    break;
                }
            }

            if start != stop - 1 {
                // subtractive path
                if type_count == MAX_UINT8 {
                    type_count = self.mtrr_lib_get_number_of_types(
                        ranges,
                        range_count,
                        vertices[start as usize].address,
                        vertices[stop as usize].address - vertices[start as usize].address,
                        Some(&mut mem_type),
                    );
                }

                let status = self.mtrr_lib_calculate_subtractive_path(
                    default_type,
                    a0,
                    ranges,
                    range_count,
                    vertex_count as u16,
                    &mut vertices,
                    weight,
                    start,
                    stop,
                    mem_type,
                    type_count,
                    Some(mtrrs),
                    Some(mtrr_capacity as usize),
                    Some(mtrr_count),
                );
                if status.is_err() {
                    break;
                }
            }

            stop = start;
        }

        for index in 0..*mtrr_count {
            println!(
                "  MTRR base_address: {:x} - {:x} mem_type: {:?}",
                mtrrs[index].base_address,
                mtrrs[index].base_address + mtrrs[index].length,
                mtrrs[index].mem_type
            );
        }

        println!("-------------------mtrr_lib_calculate_mtrrs end---------------------------");
        Ok(())
    }

    //
    //  Apply the fixed MTRR settings to memory range array.
    //
    //  @param Fixed             The fixed MTRR settings.
    //  @param Ranges            Return the memory range array holding memory type
    //                           settings for all memory address.
    //  @param RangeCapacity     The capacity of memory range array.
    //  @param RangeCount        Return the count of memory range.
    //
    //  @retval RETURN_SUCCESS          The memory range array is returned successfully.
    //  @retval RETURN_OUT_OF_RESOURCES The count of memory ranges exceeds capacity.
    //
    fn mtrr_lib_apply_fixed_mtrrs(
        &self,
        fixed: &MtrrFixedSettings,
        ranges: &mut [MtrrMemoryRange],
        range_capacity: usize,
        range_count: &mut usize,
    ) -> MtrrResult<()> {
        let mut base: u64 = 0;

        for msr_index in 0..MMTRR_LIB_FIXED_MTRR_TABLE.len() {
            assert!(base == MMTRR_LIB_FIXED_MTRR_TABLE[msr_index].base_address as u64);

            for index in 0..size_of::<u64>() {
                let memory_type: MtrrMemoryCacheType = unsafe {
                    let mem_type = *(&fixed.mtrr[msr_index] as *const u64 as *const u8).add(index);
                    mem_type.into()
                };

                let status = self.mtrr_lib_set_memory_type(
                    ranges,
                    range_capacity,
                    range_count,
                    base,
                    MMTRR_LIB_FIXED_MTRR_TABLE[msr_index].length as u64,
                    memory_type,
                );

                if status.is_err() {
                    if let MtrrError::ReturnOutOfResources = status.unwrap_err() {
                        return Err(MtrrError::ReturnOutOfResources);
                    }
                }

                base += MMTRR_LIB_FIXED_MTRR_TABLE[msr_index].length as u64;
            }
        }

        assert!(base == SIZE_1MB as u64);
        Ok(())
    }

    //
    //  Apply the variable MTRR settings to memory range array.
    //
    //  @param VariableMtrrRanges      The variable MTRR array.
    //  @param VariableMtrrRangesCount The count of variable MTRRs.
    //  @param Ranges            Return the memory range array with new MTRR settings applied.
    //  @param RangeCapacity     The capacity of memory range array.
    //  @param RangeCount        Return the count of memory range.
    //
    //  @retval RETURN_SUCCESS          The memory range array is returned successfully.
    //  @retval RETURN_OUT_OF_RESOURCES The count of memory ranges exceeds capacity.
    //
    fn mtrr_lib_apply_variable_mtrrs(
        &self,
        original_variable_mtrr_ranges: &[MtrrMemoryRange],
        original_variable_mtrr_ranges_count: u32,
        working_ranges: &mut [MtrrMemoryRange],
        working_ranges_capacity: usize,
        working_ranges_count: &mut usize,
    ) -> MtrrResult<()> {
        // println!("-------------------mtrr_lib_apply_variable_mtrrs start---------------------------");
        // 1. Set WB (Write Back)
        for index in 0..original_variable_mtrr_ranges_count as usize {
            let range = &original_variable_mtrr_ranges[index];
            // println!(
            //     "SET 1  range[{}] = {:x} - {:x} mem_type: {:?}",
            //     index,
            //     range.base_address,
            //     range.base_address + range.length,
            //     range.mem_type
            // );
            if range.length != 0 && range.mem_type == MtrrMemoryCacheType::WriteBack {
                let status = self.mtrr_lib_set_memory_type(
                    working_ranges,
                    working_ranges_capacity,
                    working_ranges_count,
                    range.base_address,
                    range.length,
                    range.mem_type,
                );
                if status.is_err() {
                    return status;
                }

                // for index2 in 0..*working_ranges_count {
                //     println!(
                //         "   SET 1  working_ranges[{}] = {:x} - {:x} mem_type: {:?}",
                //         index2,
                //         working_ranges[index2].base_address,
                //         working_ranges[index2].base_address + working_ranges[index2].length,
                //         working_ranges[index2].mem_type
                //     );
                // }
            }
        }

        // for index in 0..*working_ranges_count {
        //     println!(
        //         "SET 1  working_ranges[{}] = {:x} - {:x} mem_type: {:?}",
        //         index, working_ranges[index].base_address, working_ranges[index].base_address + working_ranges[index].length, working_ranges[index].mem_type
        //     );
        // }

        // 2. Set other types (non-WB and non-UC)
        for index in 0..original_variable_mtrr_ranges_count as usize {
            let range = &original_variable_mtrr_ranges[index];
            // println!(
            //     "SET 2  range[{}] = {:x} - {:x} mem_type: {:?}",
            //     index,
            //     range.base_address,
            //     range.base_address + range.length,
            //     range.mem_type
            // );
            if range.length != 0
                && range.mem_type != MtrrMemoryCacheType::WriteBack
                && range.mem_type != MtrrMemoryCacheType::Uncacheable
            {
                let status = self.mtrr_lib_set_memory_type(
                    working_ranges,
                    working_ranges_capacity,
                    working_ranges_count,
                    range.base_address,
                    range.length,
                    range.mem_type,
                );
                if status.is_err() {
                    return status;
                }

                // for index2 in 0..*working_ranges_count {
                //     println!(
                //         "   SET 2  working_ranges[{}] = {:x} - {:x} mem_type: {:?}",
                //         index2,
                //         working_ranges[index2].base_address,
                //         working_ranges[index2].base_address + working_ranges[index2].length,
                //         working_ranges[index2].mem_type
                //     );
                // }
            }
        }

        // 3. Set UC (Uncacheable)
        for index in 0..original_variable_mtrr_ranges_count as usize {
            let range = &original_variable_mtrr_ranges[index];
            // println!(
            //     "SET 3  range[{}] = {:x} - {:x} mem_type: {:?}",
            //     index,
            //     range.base_address,
            //     range.base_address + range.length,
            //     range.mem_type
            // );
            if range.length != 0 && range.mem_type == MtrrMemoryCacheType::Uncacheable {
                let status = self.mtrr_lib_set_memory_type(
                    working_ranges,
                    working_ranges_capacity,
                    working_ranges_count,
                    range.base_address,
                    range.length,
                    range.mem_type,
                );
                if status.is_err() {
                    return status;
                }
                // for index2 in 0..*working_ranges_count {
                //     println!(
                //         "   SET 3  working_ranges[{}] = {:x} - {:x} mem_type: {:?}",
                //         index2,
                //         working_ranges[index2].base_address,
                //         working_ranges[index2].base_address + working_ranges[index2].length,
                //         working_ranges[index2].mem_type
                //     );
                // }
            }
        }

        // for index in 0..*working_ranges_count {
        //     println!(
        //         "SET 3  working_ranges[{}] = {:x} - {:x} mem_type: {:?}",
        //         index, working_ranges[index].base_address, working_ranges[index].base_address + working_ranges[index].length, working_ranges[index].mem_type
        //     );
        // }
        // println!("-------------------mtrr_lib_apply_variable_mtrrs end---------------------------");
        Ok(())
    }

    //
    //  Return the memory type bit mask that's compatible to first type in the Ranges.
    //
    //  @param Ranges     Memory range array holding the memory type
    //                    settings for all memory address.
    //  @param RangeCount Count of memory ranges.
    //
    //  @return Compatible memory type bit mask.
    //
    fn mtrr_lib_get_compatible_types(ranges: &[MtrrMemoryRange]) -> u8 {
        assert!(!ranges.is_empty());

        let mut i = 0;

        while i < ranges.len() {
            match ranges[i].mem_type {
                MtrrMemoryCacheType::WriteBack | MtrrMemoryCacheType::WriteThrough => {
                    return (1 << MtrrMemoryCacheType::WriteBack as u8)
                        | (1 << MtrrMemoryCacheType::WriteThrough as u8)
                        | (1 << MtrrMemoryCacheType::Uncacheable as u8);
                }

                MtrrMemoryCacheType::WriteCombining | MtrrMemoryCacheType::WriteProtected => {
                    return (1 << ranges[i].mem_type as u8) | (1 << MtrrMemoryCacheType::Uncacheable as u8);
                }

                MtrrMemoryCacheType::Uncacheable => {
                    if ranges.len() == 1 {
                        return 1 << MtrrMemoryCacheType::Uncacheable as u8;
                    }
                    i += 1;
                }

                MtrrMemoryCacheType::Invalid | _ => {
                    panic!("Invalid cache type");
                }
            }
        }

        // If all ranges are MtrrMemoryCacheType::Uncacheable
        1 << MtrrMemoryCacheType::Uncacheable as u8
    }

    //
    //  Overwrite the destination MTRR settings with the source MTRR settings.
    //  This routine is to make sure the modification to destination MTRR settings
    //  is as small as possible.
    //
    //  @param DstMtrrs     Destination MTRR settings.
    //  @param DstMtrrCount Count of destination MTRR settings.
    //  @param SrcMtrrs     Source MTRR settings.
    //  @param SrcMtrrCount Count of source MTRR settings.
    //  @param Modified     Flag array to indicate which destination MTRR setting is modified.
    //
    fn mtrr_lib_merge_variable_mtrr(
        &self,
        dst_mtrrs: &mut [MtrrMemoryRange],
        dst_mtrr_count: usize,
        src_mtrrs: &mut [MtrrMemoryRange],
        src_mtrr_count: usize,
        modified: &mut [bool],
    ) {
        assert!(src_mtrr_count <= dst_mtrr_count);

        for dst_index in 0..dst_mtrr_count {
            modified[dst_index] = false;

            if dst_mtrrs[dst_index].length == 0 {
                continue;
            }

            let mut src_index = 0;
            while src_index < src_mtrr_count {
                if dst_mtrrs[dst_index].base_address == src_mtrrs[src_index].base_address
                    && dst_mtrrs[dst_index].length == src_mtrrs[src_index].length
                    && dst_mtrrs[dst_index].mem_type == src_mtrrs[src_index].mem_type
                {
                    break;
                }
                src_index += 1;
            }

            if src_index == src_mtrr_count {
                // Remove the one from dst_mtrrs that is not in src_mtrrs
                dst_mtrrs[dst_index].length = 0;
                modified[dst_index] = true;
            } else {
                // Remove the one from src_mtrrs that is also in dst_mtrrs
                src_mtrrs[src_index].length = 0;
            }
        }

        // Now valid MTRR only exists in either dst_mtrrs or src_mtrrs.
        // Merge MTRRs from src_mtrrs to dst_mtrrs
        let mut dst_index = 0;
        for src_index in 0..src_mtrr_count {
            if src_mtrrs[src_index].length != 0 {
                // Find the empty slot in dst_mtrrs
                while dst_index < dst_mtrr_count {
                    if dst_mtrrs[dst_index].length == 0 {
                        break;
                    }
                    dst_index += 1;
                }

                assert!(dst_index < dst_mtrr_count);
                dst_mtrrs[dst_index] = src_mtrrs[src_index].clone();
                modified[dst_index] = true;
            }
        }
    }

    //
    //  Calculate the variable MTRR settings for all memory ranges.
    //
    //  @param DefaultType          Default memory type.
    //  @param A0                   Alignment to use when base address is 0.
    //  @param WorkingRanges               Memory range array holding the memory type
    //                              settings for all memory address.
    //  @param WorkingRangeCount           Count of memory ranges.
    //  @param Scratch              Scratch buffer to be used in MTRR calculation.
    //  @param ScratchSize          Pointer to the size of scratch buffer.
    //  @param VariableMtrrRanges         Array holding all MTRR settings.
    //  @param VariableMtrrCapacity Capacity of the MTRR array.
    //  @param VariableMtrrRangesCount    The count of MTRR settings in array.
    //
    //  @retval RETURN_SUCCESS          Variable MTRRs are allocated successfully.
    //  @retval RETURN_OUT_OF_RESOURCES Count of variable MTRRs exceeds capacity.
    //  @retval RETURN_BUFFER_TOO_SMALL The scratch buffer is too small for MTRR calculation.
    //                                  The required scratch buffer size is returned through ScratchSize.
    //
    fn mtrr_lib_set_memory_ranges(
        &mut self,
        default_type: MtrrMemoryCacheType, // Assuming MTRR_MEMORY_CACHE_TYPE is an 8-bit enum
        a0: u64,
        working_ranges: &mut [MtrrMemoryRange],
        working_range_count: usize,
        scratch: &mut [u8],
        scratch_size: &mut usize,
        variable_mtrr_ranges: &mut [MtrrMemoryRange],
        variable_mtrr_capacity: usize,
        variable_mtrr_ranges_count: &mut usize,
    ) -> MtrrResult<()> {
        *variable_mtrr_ranges_count = 0;

        let mut biggest_scratch_size = 0;

        for i in 0..working_range_count {
            println!(
                "##### WorkingRanges[{}]  base_address: {:x} - {:x} mem_type: {:?}",
                i,
                working_ranges[i].base_address,
                working_ranges[i].base_address + working_ranges[i].length,
                working_ranges[i].mem_type
            );
        }
        let mut index = 0;
        while index < working_range_count {
            let mut base0 = working_ranges[index].base_address;

            while index < working_range_count {
                assert!(working_ranges[index].base_address == base0);

                let mut alignment = Self::mtrr_lib_biggest_alignment(base0, a0);
                println!("####### Base0: {:x} Alignment: {:x}", base0, alignment);
                while base0 + alignment <= working_ranges[index].base_address + working_ranges[index].length {
                    if biggest_scratch_size <= *scratch_size && working_ranges[index].mem_type != default_type {
                        let status = self.mtrr_lib_append_variable_mtrr(
                            variable_mtrr_ranges,
                            variable_mtrr_capacity,
                            variable_mtrr_ranges_count,
                            base0,
                            alignment,
                            working_ranges[index].mem_type,
                        );
                        println!(" status: {:?}", status);
                        if status.is_err() {
                            return status;
                        }
                    }

                    base0 += alignment;
                    alignment = Self::mtrr_lib_biggest_alignment(base0, a0);
                    println!("  ####### Base0: {:x} Alignment: {:x}", base0, alignment);
                }

                working_ranges[index].length -= base0 - working_ranges[index].base_address;
                working_ranges[index].base_address = base0;

                if working_ranges[index].length != 0 {
                    break;
                } else {
                    index += 1;
                }
            }

            if index == working_range_count {
                break;
            }

            let compatible_types = Self::mtrr_lib_get_compatible_types(&working_ranges[index..working_range_count]);
            let mut end = index;

            while (end + 1) < working_range_count {
                if (1 << working_ranges[end + 1].mem_type as u8 & compatible_types) == 0 {
                    break;
                }
                end += 1;
            }

            let alignment = Self::mtrr_lib_biggest_alignment(base0, a0);
            let length = get_power_of_two_64(working_ranges[end].base_address + working_ranges[end].length - base0);
            let base1 = base0 + core::cmp::min(alignment, length);

            println!("Base0: {:x} Base1: {:x} Length: {:x} Alignment: {:x}", base0, base1, length, alignment);
            // Base1 may not in WorkingRanges[End]. Update End to the range Base1 belongs to.
            end = index;
            while (end + 1) < working_range_count {
                if base1 <= working_ranges[end + 1].base_address {
                    break;
                }
                end += 1;
            }

            let length = working_ranges[end].length;
            working_ranges[end].length = base1 - working_ranges[end].base_address;

            let mut actual_scratch_size = *scratch_size;
            let mut status = self.mtrr_lib_calculate_mtrrs(
                default_type,
                a0,
                &working_ranges[index..end + 1],
                end + 1 - index,
                scratch,
                &mut actual_scratch_size,
                variable_mtrr_ranges,
                variable_mtrr_capacity,
                variable_mtrr_ranges_count,
            );

            if let Err(MtrrError::ReturnBufferTooSmall) = status {
                biggest_scratch_size = core::cmp::max(biggest_scratch_size, actual_scratch_size);
                // Ignore this error, because we need to calculate the biggest
                // scratch buffer size.

                status = Ok(());
            }

            if status.is_err() {
                return status;
            }

            if length != working_ranges[end].length {
                working_ranges[end].base_address = base1;
                working_ranges[end].length = length - working_ranges[end].length;
                index = end;
            } else {
                index = end + 1;
            }
        }

        if *scratch_size < biggest_scratch_size {
            *scratch_size = biggest_scratch_size;
            return Err(MtrrError::ReturnBufferTooSmall);
        }

        Ok(())
    }

    //
    //  Set the below-1MB memory attribute to fixed MTRR buffer.
    //  Modified flag array indicates which fixed MTRR is modified.
    //
    //  @param [in, out] ClearMasks    The bits (when set) to clear in the fixed MTRR MSR.
    //  @param [in, out] OrMasks       The bits to set in the fixed MTRR MSR.
    //  @param [in]      BaseAddress   Base address.
    //  @param [in]      Length        Length.
    //  @param [in]      Type          Memory type.
    //
    //  @retval RETURN_SUCCESS      The memory attribute is set successfully.
    //  @retval RETURN_UNSUPPORTED  The requested range or cache type was invalid
    //                              for the fixed MTRRs.
    //
    fn mtrr_lib_set_below_1mb_memory_attribute(
        clear_masks: &mut [u64],
        or_masks: &mut [u64],
        mut base_address: u64,
        mut length: u64,
        mem_type: MtrrMemoryCacheType,
    ) -> MtrrResult<()> {
        let mut msr_index: u32;
        let mut clear_mask: u64 = 0;
        let mut or_mask: u64 = 0;

        assert!(base_address < SIZE_1MB as u64);

        msr_index = u32::MAX;

        while base_address < SIZE_1MB as u64 && length != 0 {
            let status = Self::mtrr_lib_program_fixed_mtrr(
                mem_type as u8,
                &mut base_address,
                &mut length,
                &mut msr_index,
                &mut clear_mask,
                &mut or_mask,
            );

            if status.is_err() {
                return status;
            }

            clear_masks[msr_index as usize] |= clear_mask;
            or_masks[msr_index as usize] = (or_masks[msr_index as usize] & !clear_mask) | or_mask;
        }

        Ok(())
    }

    //
    //  This function attempts to set the attributes into MTRR setting buffer for multiple memory ranges.
    //
    //  @param[in, out]  MtrrSetting  MTRR setting buffer to be set.
    //  @param[in]       Scratch      A temporary scratch buffer that is used to perform the calculation.
    //  @param[in, out]  ScratchSize  Pointer to the size in bytes of the scratch buffer.
    //                                It may be updated to the actual required size when the calculation
    //                                needs more scratch buffer.
    //  @param[in]       Ranges       Pointer to an array of MTRR_MEMORY_RANGE.
    //                                When range overlap happens, the last one takes higher priority.
    //                                When the function returns, either all the attributes are set successfully,
    //                                or none of them is set.
    //  @param[in]       WorkingRangeCount   Count of MTRR_MEMORY_RANGE.
    //
    //  @retval RETURN_SUCCESS            The attributes were set for all the memory ranges.
    //  @retval RETURN_INVALID_PARAMETER  Length in any range is zero.
    //  @retval RETURN_UNSUPPORTED        The processor does not support one or more bytes of the
    //                                    memory resource range specified by BaseAddress and Length in any range.
    //  @retval RETURN_UNSUPPORTED        The bit mask of attributes is not support for the memory resource
    //                                    range specified by BaseAddress and Length in any range.
    //  @retval RETURN_OUT_OF_RESOURCES   There are not enough system resources to modify the attributes of
    //                                    the memory resource ranges.
    //  @retval RETURN_ACCESS_DENIED      The attributes for the memory resource range specified by
    //                                    BaseAddress and Length cannot be modified.
    //  @retval RETURN_BUFFER_TOO_SMALL   The scratch buffer is too small for MTRR calculation.
    //
    fn mtrr_set_memory_attributes_internal(
        &mut self,
        scratch: &mut [u8],
        scratch_size: &mut usize,
        ranges: &[MtrrMemoryRange],
        range_count: usize,
    ) -> MtrrResult<()> {
        let mut status;
        let mut variable_mtrr_needed;
        let mut modified: bool;
        let mut base_address: u64;
        let mut length: u64;

        let default_type: MtrrMemoryCacheType;
        let mut working_ranges: [MtrrMemoryRange; MTRR_NUMBER_OF_WORKING_MTRR_RANGES] =
            [MtrrMemoryRange::default(); MTRR_NUMBER_OF_WORKING_MTRR_RANGES];
        let mut working_range_count;
        let firmware_variable_mtrr_count: u32;
        let mut working_variable_mtrr_ranges_count: usize = 0;
        let mut original_variable_mtrr_ranges: [MtrrMemoryRange; MTRR_NUMBER_OF_VARIABLE_MTRR] = Default::default();
        let mut working_variable_mtrr_ranges: [MtrrMemoryRange; MTRR_NUMBER_OF_VARIABLE_MTRR] = Default::default();
        let mut variable_setting_modified: [bool; MTRR_NUMBER_OF_VARIABLE_MTRR] = [false; MTRR_NUMBER_OF_VARIABLE_MTRR];

        let fixed_mtrr_memory_limit: u64;
        let mut clear_masks: [u64; 11] = [0; 11];
        let mut or_masks: [u64; 11] = [0; 11];

        let mut mtrr_context = MtrrContext::default();
        let mut mtrr_context_valid = false;

        // Initialize MTRR Mask
        let (mtrr_valid_bits_mask, mtrr_valid_address_mask) = self.mtrr_lib_initialize_mtrr_mask();

        // Set memory attributes
        variable_mtrr_needed = false;

        // Dump the requests for debugging
        // TODO: VINEEL Enable dumping
        println!(
            "Mtrr: Set Mem Attribute to Hardware, ScratchSize = {}{}",
            *scratch_size,
            if range_count <= 1 { "," } else { "\n" }
        );
        for index in 0..range_count {
            println!(
                "{:?}  [{:016x}, {:016x})\n",
                ranges[index].mem_type,
                ranges[index].base_address,
                ranges[index].base_address + ranges[index].length
            );
        }

        // 1. Validate the parameters
        let Ok((fixed_mtrr_supported, original_variable_mtrr_ranges_count)) =
            self.mtrr_lib_is_mtrr_supported_internal()
        else {
            return Err(MtrrError::ReturnUnsupported);
        };

        fixed_mtrr_memory_limit = if fixed_mtrr_supported { SIZE_1MB as u64 } else { 0 };

        for index in 0..range_count {
            if ranges[index].length == 0 {
                return Err(MtrrError::ReturnInvalidParameter);
            }

            if (ranges[index].base_address & !mtrr_valid_address_mask) != 0
                || ((ranges[index].base_address + ranges[index].length) & !mtrr_valid_address_mask) != 0
                    && (ranges[index].base_address + ranges[index].length) != mtrr_valid_bits_mask + 1
            {
                return Err(MtrrError::ReturnUnsupported);
            }

            if !matches!(
                ranges[index].mem_type,
                MtrrMemoryCacheType::Uncacheable
                    | MtrrMemoryCacheType::WriteCombining
                    | MtrrMemoryCacheType::WriteThrough
                    | MtrrMemoryCacheType::WriteProtected
                    | MtrrMemoryCacheType::WriteBack
            ) {
                return Err(MtrrError::ReturnInvalidParameter);
            }

            if ranges[index].base_address + ranges[index].length > fixed_mtrr_memory_limit {
                variable_mtrr_needed = true;
            }
        }

        // 2. Apply the above-1MB memory attribute settings
        if variable_mtrr_needed {
            // 2.1. Read all variable MTRRs and convert to Ranges.
            let variable_mtrr_settings = self.mtrr_get_variable_mtrr(original_variable_mtrr_ranges_count);
            Self::mtrr_lib_get_variable_memory_ranges(
                &variable_mtrr_settings,
                original_variable_mtrr_ranges_count as usize,
                mtrr_valid_bits_mask,
                mtrr_valid_address_mask,
                &mut original_variable_mtrr_ranges,
            );

            default_type = self.mtrr_get_default_memory_type();
            working_range_count = 1;
            working_ranges[0].base_address = 0;
            working_ranges[0].length = mtrr_valid_bits_mask + 1;
            working_ranges[0].mem_type = default_type;

            status = self.mtrr_lib_apply_variable_mtrrs(
                &original_variable_mtrr_ranges,
                original_variable_mtrr_ranges_count,
                &mut working_ranges,
                MTRR_NUMBER_OF_WORKING_MTRR_RANGES,
                &mut working_range_count,
            );

            if status.is_err() {
                return status;
            }

            println!("mtrr_lib_apply_variable_mtrrs Working range count: {}", working_range_count);
            for index in 0..working_range_count {
                println!(
                    "Working range: {}: [{:016x}, {:016x}) {:?}\n",
                    index,
                    working_ranges[index].base_address,
                    working_ranges[index].base_address + working_ranges[index].length,
                    working_ranges[index].mem_type as u8,
                );
            }

            assert!(original_variable_mtrr_ranges_count >= self.hal.get_pcd_cpu_number_of_reserved_variable_mtrrs());

            firmware_variable_mtrr_count =
                original_variable_mtrr_ranges_count - self.hal.get_pcd_cpu_number_of_reserved_variable_mtrrs();
            assert!(working_range_count <= 2 * firmware_variable_mtrr_count as usize + 1);

            // 2.2. Force [0, 1M) to UC, so that it doesn't impact subtraction algorithm.

            if fixed_mtrr_memory_limit != 0 {
                status = self.mtrr_lib_set_memory_type(
                    &mut working_ranges,
                    MTRR_NUMBER_OF_WORKING_MTRR_RANGES,
                    &mut working_range_count,
                    0,
                    fixed_mtrr_memory_limit,
                    MtrrMemoryCacheType::Uncacheable,
                );
                if status.is_err() {
                    assert!(status.err().unwrap() != MtrrError::ReturnOutOfResources);
                }
            }

            // 2.3. Apply the new memory attribute settings to Ranges.
            println!("Step 2.3");
            modified = false;
            for index in 0..range_count {
                base_address = ranges[index].base_address;
                length = ranges[index].length;
                if base_address < fixed_mtrr_memory_limit {
                    if length <= fixed_mtrr_memory_limit - base_address {
                        continue;
                    }

                    length -= fixed_mtrr_memory_limit - base_address;
                    base_address = fixed_mtrr_memory_limit;
                }

                status = self.mtrr_lib_set_memory_type(
                    &mut working_ranges,
                    MTRR_NUMBER_OF_WORKING_MTRR_RANGES,
                    &mut working_range_count,
                    base_address,
                    length,
                    ranges[index].mem_type,
                );
                if let Err(MtrrError::ReturnAlreadyStarted) = status {
                    // status = Ok(());
                } else if status.is_err() {
                    return status;
                } else {
                    if status.is_err() {
                        return status;
                    }
                    modified = true;
                }
            }

            for index2 in 0..working_range_count {
                println!(
                    "Working range: {}: [{:016x}, {:016x}) {:?}\n",
                    index2,
                    working_ranges[index2].base_address,
                    working_ranges[index2].base_address + working_ranges[index2].length,
                    working_ranges[index2].mem_type as u8,
                );
            }
            if modified {
                // 2.4. Calculate the Variable MTRR settings based on the Ranges.
                //      Buffer Too Small may be returned if the scratch buffer size is insufficient.
                println!(
                    "mtrr_valid_bits_mask: {:016x} mtrr_valid_address_mask:  {:016x}",
                    mtrr_valid_bits_mask, mtrr_valid_address_mask
                );
                println!("high_bit_set_64(mtrr_valid_bits_mask) = {}", high_bit_set_64(mtrr_valid_bits_mask));
                println!("a0: {:016x} ", 1u64 << high_bit_set_64(mtrr_valid_bits_mask));
                println!("Step 2.4");
                status = self.mtrr_lib_set_memory_ranges(
                    default_type,
                    1 << high_bit_set_64(mtrr_valid_bits_mask),
                    &mut working_ranges,
                    working_range_count,
                    scratch,
                    scratch_size,
                    &mut working_variable_mtrr_ranges,
                    (firmware_variable_mtrr_count + 1) as usize,
                    &mut working_variable_mtrr_ranges_count,
                );
                if status.is_err() {
                    return status;
                }

                // 2.5. Remove the [0, 1MB) MTRR if it still exists (not merged with other range)
                for index in 0..working_variable_mtrr_ranges_count as usize {
                    if working_variable_mtrr_ranges[index].base_address == 0
                        && working_variable_mtrr_ranges[index].length == fixed_mtrr_memory_limit
                    {
                        assert!(working_variable_mtrr_ranges[index].mem_type == MtrrMemoryCacheType::Uncacheable);
                        working_variable_mtrr_ranges_count -= 1;

                        for i in 0..(working_variable_mtrr_ranges_count - index) {
                            working_variable_mtrr_ranges[i + index] =
                                working_variable_mtrr_ranges[i + index + 1].clone();
                        }

                        break;
                    }
                }

                if working_variable_mtrr_ranges_count > firmware_variable_mtrr_count as usize {
                    return Err(MtrrError::ReturnOutOfResources);
                }

                println!("Step 2.6");
                // 2.6. Merge the WorkingVariableMtrrRanges to OriginalVariableMtrrRanges
                //      Make sure least modification is made to OriginalVariableMtrrRanges.
                self.mtrr_lib_merge_variable_mtrr(
                    &mut original_variable_mtrr_ranges,
                    original_variable_mtrr_ranges_count as usize,
                    &mut working_variable_mtrr_ranges,
                    working_variable_mtrr_ranges_count,
                    &mut variable_setting_modified,
                );
            }
        }

        // 3. Apply the below-1MB memory attribute settings
        clear_masks.fill(0);
        or_masks.fill(0);
        println!("Step 3");
        for index in 0..range_count {
            if ranges[index].base_address >= fixed_mtrr_memory_limit {
                continue;
            }

            status = Self::mtrr_lib_set_below_1mb_memory_attribute(
                &mut clear_masks,
                &mut or_masks,
                ranges[index].base_address,
                ranges[index].length,
                ranges[index].mem_type,
            );
            if status.is_err() {
                return status;
            }
        }

        // 4. Write fixed MTRRs that have been modified
        for (index, &clear_mask) in clear_masks.iter().enumerate() {
            if clear_mask != 0 {
                if !mtrr_context_valid {
                    self.mtrr_lib_pre_mtrr_change(&mut mtrr_context);
                    mtrr_context.def_type.set_fe(true);
                    mtrr_context_valid = true;
                }

                self.hal.asm_msr_and_then_or_64(MMTRR_LIB_FIXED_MTRR_TABLE[index].msr, !clear_mask, or_masks[index]);
            }
        }

        // 5. Write variable MTRRs that have been modified
        for index in 0..original_variable_mtrr_ranges_count as usize {
            if variable_setting_modified[index] {
                let variable_setting = if original_variable_mtrr_ranges[index].length != 0 {
                    let base = (original_variable_mtrr_ranges[index].base_address & mtrr_valid_address_mask)
                        | (original_variable_mtrr_ranges[index].mem_type as u64);
                    let mask = ((!(original_variable_mtrr_ranges[index].length - 1)) & mtrr_valid_address_mask) | BIT11;

                    MtrrVariableSetting { base, mask }
                } else {
                    MtrrVariableSetting { base: 0, mask: 0 }
                };

                if !mtrr_context_valid {
                    self.mtrr_lib_pre_mtrr_change(&mut mtrr_context);
                    mtrr_context_valid = true;
                }

                self.hal.asm_write_msr64(MSR_IA32_MTRR_PHYSBASE0 + (index as u32 * 2), variable_setting.base);
                self.hal.asm_write_msr64(MSR_IA32_MTRR_PHYSMASK0 + (index as u32 * 2), variable_setting.mask);
            }
        }

        if mtrr_context_valid {
            self.mtrr_lib_post_mtrr_change(&mut mtrr_context);
        }

        self.mtrr_debug_print_all_mtrrs();

        Ok(())
    }

    //
    //  This function attempts to set the attributes into MTRR setting buffer for a memory range.
    //
    //  @param[in, out]  MtrrSetting  MTRR setting buffer to be set.
    //  @param[in]       BaseAddress  The physical address that is the start address
    //                                of a memory range.
    //  @param[in]       Length       The size in bytes of the memory range.
    //  @param[in]       Attribute    The bit mask of attributes to set for the
    //                                memory range.
    //
    //  @retval RETURN_SUCCESS            The attributes were set for the memory range.
    //  @retval RETURN_INVALID_PARAMETER  Length is zero.
    //  @retval RETURN_UNSUPPORTED        The processor does not support one or more bytes of the
    //                                    memory resource range specified by BaseAddress and Length.
    //  @retval RETURN_UNSUPPORTED        The bit mask of attributes is not support for the memory resource
    //                                    range specified by BaseAddress and Length.
    //  @retval RETURN_ACCESS_DENIED      The attributes for the memory resource range specified by
    //                                    BaseAddress and Length cannot be modified.
    //  @retval RETURN_OUT_OF_RESOURCES   There are not enough system resources to modify the attributes of
    //                                    the memory resource range.
    //                                    Multiple memory range attributes setting by calling this API multiple
    //                                    times may fail with status RETURN_OUT_OF_RESOURCES. It may not mean
    //                                    the number of CPU MTRRs are too small to set such memory attributes.
    //                                    Pass the multiple memory range attributes to one call of
    //                                    MtrrSetMemoryAttributesInMtrrSettings() may succeed.
    //  @retval RETURN_BUFFER_TOO_SMALL   The fixed internal scratch buffer is too small for MTRR calculation.
    //                                    Caller should use MtrrSetMemoryAttributesInMtrrSettings() to specify
    //                                    external scratch buffer.
    //
    pub fn mtrr_set_memory_attributes(
        &mut self,
        ranges: &[MtrrMemoryRange],
    ) -> MtrrResult<()> {
        let mut scratch: [u8; SCRATCH_BUFFER_SIZE] = [0; SCRATCH_BUFFER_SIZE];
        let mut scratch_size = scratch.len();

        self.mtrr_set_memory_attributes_internal(&mut scratch, &mut scratch_size, ranges, ranges.len())
    }

    //
    //  This function attempts to set the attributes for a memory range.
    //
    //  @param[in]  BaseAddress        The physical address that is the start
    //                                 address of a memory range.
    //  @param[in]  Length             The size in bytes of the memory range.
    //  @param[in]  Attributes         The bit mask of attributes to set for the
    //                                 memory range.
    //
    //  @retval RETURN_SUCCESS            The attributes were set for the memory
    //                                    range.
    //  @retval RETURN_INVALID_PARAMETER  Length is zero.
    //  @retval RETURN_UNSUPPORTED        The processor does not support one or
    //                                    more bytes of the memory resource range
    //                                    specified by BaseAddress and Length.
    //  @retval RETURN_UNSUPPORTED        The bit mask of attributes is not support
    //                                    for the memory resource range specified
    //                                    by BaseAddress and Length.
    //  @retval RETURN_ACCESS_DENIED      The attributes for the memory resource
    //                                    range specified by BaseAddress and Length
    //                                    cannot be modified.
    //  @retval RETURN_OUT_OF_RESOURCES   There are not enough system resources to
    //                                    modify the attributes of the memory
    //                                    resource range.
    //                                    Multiple memory range attributes setting by calling this API multiple
    //                                    times may fail with status RETURN_OUT_OF_RESOURCES. It may not mean
    //                                    the number of CPU MTRRs are too small to set such memory attributes.
    //                                    Pass the multiple memory range attributes to one call of
    //                                    MtrrSetMemoryAttributesInMtrrSettings() may succeed.
    //  @retval RETURN_BUFFER_TOO_SMALL   The fixed internal scratch buffer is too small for MTRR calculation.
    //                                    Caller should use MtrrSetMemoryAttributesInMtrrSettings() to specify
    //                                    external scratch buffer.
    //
    pub fn mtrr_set_memory_attribute(
        &mut self,
        base_address: u64,
        length: u64,
        attribute: MtrrMemoryCacheType,
    ) -> MtrrResult<()> {
        let mut scratch: [u8; SCRATCH_BUFFER_SIZE] = [0; SCRATCH_BUFFER_SIZE];
        let mut scratch_size = scratch.len();

        let range = MtrrMemoryRange { base_address, length, mem_type: attribute };

        self.mtrr_set_memory_attributes_internal(&mut scratch, &mut scratch_size, &[range], 1)
    }

    //
    //  Worker function setting variable MTRRs
    //
    //  @param[in]  VariableMtrrSettings   A buffer to hold variable MTRRs content.
    //
    fn mtrr_set_variable_mtrr(&mut self, variable_mtrr_settings: &MtrrVariableSettings) {
        let variable_mtrr_ranges_count = self.get_variable_mtrr_count();
        assert!(variable_mtrr_ranges_count <= MTRR_NUMBER_OF_VARIABLE_MTRR as u32);

        for index in 0..variable_mtrr_ranges_count {
            let base_msr = MSR_IA32_MTRR_PHYSBASE0 + (index << 1);
            let mask_msr = MSR_IA32_MTRR_PHYSMASK0 + (index << 1);

            self.hal.asm_write_msr64(base_msr, variable_mtrr_settings.mtrr[index as usize].base);
            self.hal.asm_write_msr64(mask_msr, variable_mtrr_settings.mtrr[index as usize].mask);
        }
    }

    //
    //  Worker function setting fixed MTRRs
    //
    //  @param[in]  FixedSettings  A buffer to hold fixed MTRRs content.
    //
    fn mtrr_set_fixed_mtrr(&mut self, fixed_settings: &MtrrFixedSettings) {
        for index in 0..MTRR_NUMBER_OF_FIXED_MTRR {
            let msr = MMTRR_LIB_FIXED_MTRR_TABLE[index].msr;
            let value = fixed_settings.mtrr[index];
            self.hal.asm_write_msr64(msr, value);
        }
    }

    //
    //  This function gets the content in all MTRRs (variable and fixed)
    //
    //  @param[out]  MtrrSetting  A buffer to hold all MTRRs content.
    //
    //  @retval the pointer of MtrrSetting
    //
    pub fn mtrr_get_all_mtrrs(&self) -> MtrrSettings {
        // Initialize the MTRR settings
        let mut mtrr_setting = MtrrSettings::default();

        // Check if MTRR is supported
        let Ok((fixed_mtrr_supported, variable_mtrr_ranges_count)) = self.mtrr_lib_is_mtrr_supported_internal() else {
            return mtrr_setting;
        };

        // Get MTRR_DEF_TYPE value
        let mtrr_def_type = MsrIa32MtrrDefType::from_bits(self.hal.asm_read_msr64(MSR_IA32_MTRR_DEF_TYPE));

        // Assert that enabling the Fixed MTRR bit when unsupported is not allowed
        assert!(fixed_mtrr_supported || !mtrr_def_type.fe());

        mtrr_setting.mtrr_def_type_reg = mtrr_def_type.into();

        // Get fixed MTRRs if supported
        if mtrr_def_type.fe() {
            mtrr_setting.fixed = self.mtrr_get_fixed_mtrr();
        }

        // Get variable MTRRs
        mtrr_setting.variables = self.mtrr_get_variable_mtrr(variable_mtrr_ranges_count);
        mtrr_setting
    }

    //
    //  This function sets all MTRRs includes Variable and Fixed.
    //
    //  The behavior of this function is to program everything in MtrrSetting to hardware.
    //  MTRRs might not be enabled because the enable bit is clear in MtrrSetting->MtrrDefType.
    //
    //  @param[in]  MtrrSetting  A buffer holding all MTRRs content.
    //
    //  @retval The pointer of MtrrSetting
    //
    pub fn mtrr_set_all_mtrrs(&mut self, mtrr_setting: &MtrrSettings) {
        let mut mtrr_context = MtrrContext::default();

        // Check if MTRR is supported
        let Ok((fixed_mtrr_supported, _)) = self.mtrr_lib_is_mtrr_supported_internal() else {
            return;
        };

        // Prepare for MTRR change
        self.mtrr_lib_pre_mtrr_change(&mut mtrr_context);

        // Assert that enabling Fixed MTRR when unsupported is not allowed
        assert!(fixed_mtrr_supported || !mtrr_setting.mtrr_def_type_reg.fe());

        // If hardware supports Fixed MTRR, set Fixed MTRRs
        if fixed_mtrr_supported {
            self.mtrr_set_fixed_mtrr(&mtrr_setting.fixed);
        }

        // Set Variable MTRRs
        self.mtrr_set_variable_mtrr(&mtrr_setting.variables);

        // Set MTRR_DEF_TYPE value
        self.hal.asm_write_msr64(MSR_IA32_MTRR_DEF_TYPE, mtrr_setting.mtrr_def_type_reg.into_bits());

        // Finalize MTRR change and enable cache
        self.mtrr_lib_post_mtrr_change_enable_cache(&mut mtrr_context);
    }

    //
    //  Checks if MTRR is supported.
    //
    //  @retval TRUE  MTRR is supported.
    //  @retval FALSE MTRR is not supported.
    //
    pub fn is_mtrr_supported(&self) -> bool {
        self.mtrr_lib_is_mtrr_supported_internal().is_ok()
    }

    //
    //  This function returns a Ranges array containing the memory cache types
    //  of all memory addresses.
    //
    //  @param[in]      MtrrSetting  MTRR setting buffer to parse.
    //  @param[out]     Ranges       Pointer to an array of MTRR_MEMORY_RANGE.
    //  @param[in,out]  RangeCount   Count of MTRR_MEMORY_RANGE.
    //                               On input, the maximum entries the Ranges can hold.
    //                               On output, the actual entries that the function returns.
    //
    //  @retval RETURN_INVALID_PARAMETER RangeCount is NULL.
    //  @retval RETURN_INVALID_PARAMETER *RangeCount is not 0 but Ranges is NULL.
    //  @retval RETURN_BUFFER_TOO_SMALL  *RangeCount is too small.
    //  @retval RETURN_SUCCESS           Ranges are successfully returned.
    //
    pub fn mtrr_get_memory_ranges(
        &self,
        ranges: &mut [MtrrMemoryRange],
        range_count: Option<&mut usize>,
    ) -> MtrrResult<()> {
        // Define the local structures and variables
        let mtrrs: MtrrSettings;
        let mut raw_variable_ranges: [MtrrMemoryRange; MTRR_NUMBER_OF_VARIABLE_MTRR] = Default::default();
        let mut all_ranges: [MtrrMemoryRange; MTRR_NUMBER_OF_LOCAL_MTRR_RANGES] =
            [MtrrMemoryRange::default(); MTRR_NUMBER_OF_LOCAL_MTRR_RANGES];

        let mut all_range_count = 1;

        // Validate parameters
        if range_count.is_none() {
            return Err(MtrrError::ReturnInvalidParameter);
        }

        let range_count = range_count.unwrap();

        if *range_count != 0 && ranges.is_empty() {
            return Err(MtrrError::ReturnInvalidParameter);
        }

        // Determine the MTRR settings to use
        mtrrs = self.mtrr_get_all_mtrrs();

        // Initialize the MTRR masks
        let (mtrr_valid_bits_mask, mtrr_valid_address_mask) = self.mtrr_lib_initialize_mtrr_mask();

        // Start with the one big range[0, mtrr_valid_bits_mask] and the default memory type
        all_ranges[0] = MtrrMemoryRange { base_address: 0, length: mtrr_valid_bits_mask + 1, ..Default::default() };

        let mtrr_def_type = MsrIa32MtrrDefType::from(mtrrs.mtrr_def_type_reg);

        if !mtrr_def_type.e() {
            all_ranges[0].mem_type = MtrrMemoryCacheType::Uncacheable;
        } else {
            all_ranges[0].mem_type = self.mtrr_get_default_memory_type();

            let variable_mtrr_ranges_count = self.get_variable_mtrr_count();
            assert!(variable_mtrr_ranges_count <= MTRR_NUMBER_OF_VARIABLE_MTRR as u32);

            Self::mtrr_lib_get_variable_memory_ranges(
                &mtrrs.variables,
                variable_mtrr_ranges_count as usize,
                mtrr_valid_bits_mask,
                mtrr_valid_address_mask,
                &mut raw_variable_ranges,
            );

            let status = self.mtrr_lib_apply_variable_mtrrs(
                &raw_variable_ranges,
                variable_mtrr_ranges_count,
                &mut all_ranges,
                MTRR_NUMBER_OF_LOCAL_MTRR_RANGES,
                &mut all_range_count,
            );

            if status.is_err() {
                return status;
            }

            if mtrr_def_type.fe() {
                let _ = self.mtrr_lib_apply_fixed_mtrrs(
                    &mtrrs.fixed,
                    &mut all_ranges,
                    MTRR_NUMBER_OF_LOCAL_MTRR_RANGES,
                    &mut all_range_count,
                );
            }
        }

        if *range_count < all_range_count {
            *range_count = all_range_count;
            return Err(MtrrError::ReturnBufferTooSmall);
        }

        for i in 0..all_range_count {
            ranges[i] = all_ranges[i];
        }
        *range_count = all_range_count;
        Ok(())
    }

    //
    //  This function prints all MTRRs for debugging.
    //
    //  If MtrrSetting is not NULL, print MTRR settings from input MTRR
    //  settings buffer.
    //  If MtrrSetting is NULL, print MTRR settings from MTRRs.
    //
    //  @param  MtrrSetting    A buffer holding all MTRRs content.
    //
    pub fn mtrr_debug_print_all_mtrrs(&self) {
        // Initialize local variables
        let mtrrs: MtrrSettings;
        let status;
        let mut range_count: usize;
        let mut contain_variable_mtrr = false;

        // Fixed-size arrays instead of vectors
        let mut ranges: [MtrrMemoryRange; MTRR_NUMBER_OF_LOCAL_MTRR_RANGES] =
            [MtrrMemoryRange::default(); MTRR_NUMBER_OF_LOCAL_MTRR_RANGES];

        // Determine which MTRR settings to use
        mtrrs = self.mtrr_get_all_mtrrs();

        range_count = ranges.len();
        status = self.mtrr_get_memory_ranges(&mut ranges, Some(&mut range_count));

        if status.is_err() {
            println!("MTRR is not enabled.");
            return;
        }

        // Dump RAW MTRR contents
        println!("MTRR Settings:");
        println!("=============");
        println!("MTRR Default Type: {:#016x}", mtrrs.mtrr_def_type_reg.into_bits());

        for index in 0..MMTRR_LIB_FIXED_MTRR_TABLE.len() {
            println!("Fixed MTRR[{:02}]   : {:#016x}", index, mtrrs.fixed.mtrr[index]);
        }

        for index in 0..mtrrs.variables.mtrr.len() {
            if mtrrs.variables.mtrr[index].mask & (1 << 11) == 0 {
                // If mask is not valid, then do not display range
                continue;
            }

            contain_variable_mtrr = true;
            println!(
                "Variable MTRR[{:02}]: Base={:#016x} Mask={:#016x}",
                index, mtrrs.variables.mtrr[index].base, mtrrs.variables.mtrr[index].mask
            );
        }

        if !contain_variable_mtrr {
            println!("Variable MTRR    : None.");
        }

        // println!();

        // Dump MTRR setting in ranges
        println!("Memory Ranges:");
        println!("====================================");
        for index in 0..range_count {
            let cache_type_name = MMTRR_MEMORY_CACHE_TYPE_SHORT_NAME[ranges[index].mem_type as usize];
            println!(
                "{}:{:#016x}-{:#016x}",
                cache_type_name,
                ranges[index].base_address,
                ranges[index].base_address + ranges[index].length - 1
            );
        }
    }

    //
    //  Few tests require reusing the hal passed to MtrrLib for validation
    //  purposes towards the end of the tests. So this function basically
    //  consumes the MtrrLib and returns the hal.
    //
    //  @return Firmware usable variable MTRR count
    //
    #[cfg(test)]
    pub(crate) fn mtrr_drop_hal(self) -> H {
        self.hal
    }

    //
    //  Returns the firmware usable variable MTRR count for the CPU.
    //
    //  @return Firmware usable variable MTRR count
    //
    #[cfg(test)]
    pub(crate) fn get_firmware_usable_variable_mtrr_count(&self) -> u32 {
        if !self.is_mtrr_supported() {
            return 0;
        }

        // Assuming the existence of these functions
        let variable_mtrr_ranges_count = self.get_variable_mtrr_count();
        let reserved_mtrr_number = self.hal.get_pcd_cpu_number_of_reserved_variable_mtrrs();

        if variable_mtrr_ranges_count < reserved_mtrr_number {
            return 0;
        }

        variable_mtrr_ranges_count - reserved_mtrr_number
    }

    //
    //  Gets the attribute of variable MTRRs.
    //
    //  This function shadows the content of variable MTRRs into an
    //  internal array: VariableMtrrRanges.
    //
    //  @param[in]   MtrrValidBitsMask     The mask for the valid bit of the MTRR
    //  @param[in]   MtrrValidAddressMask  The valid address mask for MTRR
    //  @param[out]  VariableMtrrRanges          The array to shadow variable MTRRs content
    //
    //  @return                       The return value of this parameter indicates the
    //                                number of MTRRs which has been used.
    //
    #[cfg(test)]
    pub(crate) fn mtrr_get_memory_attribute_in_variable_mtrr(
        &self,
        mtrr_valid_bits_mask: u64,
        mtrr_valid_address_mask: u64,
    ) -> Vec<VariableMtrr> {
        let mut variable_mtrr_ranges: Vec<VariableMtrr> = Vec::new();

        // Check if MTRR is supported
        if !self.is_mtrr_supported() {
            return variable_mtrr_ranges;
        }

        let ranges_count = self.get_variable_mtrr_count();

        // Get the variable MTRR settings
        let variable_mtrr_settings = self.mtrr_get_variable_mtrr(ranges_count);

        let firmware_variable_mtrr_count = self.get_firmware_usable_variable_mtrr_count();

        for index in 0..firmware_variable_mtrr_count as usize {
            let entry = &variable_mtrr_settings.mtrr[index];
            let mask = entry.mask;
            let base = entry.base;

            // Check if the MTRR is valid
            if (mask >> 11) & 1 != 0 {
                variable_mtrr_ranges.push(VariableMtrr {
                    msr: index as u32,
                    base_address: base & mtrr_valid_address_mask,
                    length: ((!(mask & mtrr_valid_address_mask)) & mtrr_valid_bits_mask) + 1,
                    mem_type: (base & 0xff) as u8,
                    valid: true,
                    used: true,
                });
            } else {
                variable_mtrr_ranges.push(VariableMtrr::default());
            }
        }

        variable_mtrr_ranges
    }
}

pub fn create_mtrr_lib() -> MtrrLib {
    let hal = Hal::new();
    MtrrLib::new(hal)
}
