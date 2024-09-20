#[allow(unused_imports)]
use core::arch::asm;
use core::arch::x86_64::CpuidResult;

use mtrr::hal::HalTrait;
use mtrr::mtrr::MtrrLib;
use mtrr::structs::CpuidStructuredExtendedFeatureFlagsEcx;
use mtrr::structs::CpuidVersionInfoEdx;
use mtrr::structs::CpuidVirPhyAddressSizeEax;
use mtrr::structs::MsrIa32MtrrDefType;
use mtrr::structs::MsrIa32MtrrPhysbaseRegister;
use mtrr::structs::MsrIa32MtrrPhysmaskRegister;
use mtrr::structs::MsrIa32MtrrcapRegister;
use mtrr::structs::MsrIa32TmeActivateRegister;
use mtrr::structs::CPUID_EXTENDED_FUNCTION;
use mtrr::structs::CPUID_SIGNATURE;
use mtrr::structs::CPUID_VERSION_INFO;
use mtrr::structs::CPUID_VIR_PHY_ADDRESS_SIZE;
use mtrr::structs::MSR_IA32_MTRRCAP;
use mtrr::structs::MSR_IA32_MTRR_DEF_TYPE;
use mtrr::structs::MSR_IA32_MTRR_PHYSBASE0;
use mtrr::structs::MSR_IA32_MTRR_PHYSMASK0;
use mtrr::structs::MSR_IA32_TME_ACTIVATE;
use mtrr::structs::MTRR_NUMBER_OF_FIXED_MTRR;
use mtrr::structs::MTRR_NUMBER_OF_VARIABLE_MTRR;

use crate::common::structs::MtrrLibSystemParameter;
use crate::common::structs::M_FIXED_MTRRS_INDEX;

pub fn create_mtrr_lib_with_mock_hal(hal: MockHal) -> MtrrLib<MockHal> {
    let mtrr_lib = MtrrLib::new(hal);
    mtrr_lib
}

pub struct MockHal {
    fixed_mtrrs_value: [u64; MTRR_NUMBER_OF_FIXED_MTRR],
    variable_mtrrs_phys_base: [MsrIa32MtrrPhysbaseRegister; MTRR_NUMBER_OF_VARIABLE_MTRR],
    variable_mtrrs_phys_mask: [MsrIa32MtrrPhysmaskRegister; MTRR_NUMBER_OF_VARIABLE_MTRR],
    def_type_msr: MsrIa32MtrrDefType,
    mtrr_cap_msr: MsrIa32MtrrcapRegister,
    tme_activate_msr: MsrIa32TmeActivateRegister,
    cpuid_version_info_edx: CpuidVersionInfoEdx,
    cpuid_extended_feature_flags_ecx: CpuidStructuredExtendedFeatureFlagsEcx,
    cpuid_vir_phy_address_size_eax: CpuidVirPhyAddressSizeEax,

    // Mocked hal functions state. Replicated from
    // mu_tiano_platforms\MU_BASECORE\MdePkg\Library\BaseLib\X86UnitTestHost.c
    interrupt_state: bool,
    cr3: u64,
    cr4: u64,
    pcd_cpu_number_of_reserved_variable_mtrrs: u32,
}

impl MockHal {
    pub fn new() -> Self {
        Self {
            fixed_mtrrs_value: Default::default(),
            variable_mtrrs_phys_base: Default::default(),
            variable_mtrrs_phys_mask: Default::default(),
            def_type_msr: Default::default(),
            mtrr_cap_msr: Default::default(),
            tme_activate_msr: Default::default(),
            cpuid_version_info_edx: Default::default(),
            cpuid_extended_feature_flags_ecx: Default::default(),
            cpuid_vir_phy_address_size_eax: Default::default(),
            interrupt_state: true,
            cr3: 0,
            cr4: 0,
            pcd_cpu_number_of_reserved_variable_mtrrs: 0,
        }
    }

    pub fn initialize_mtrr_regs(&mut self, system_parameter: &MtrrLibSystemParameter) {
        for value in &mut self.fixed_mtrrs_value {
            *value = system_parameter.default_cache_type as u64;
        }

        for i in 0..MTRR_NUMBER_OF_VARIABLE_MTRR {
            self.variable_mtrrs_phys_base[i] = MsrIa32MtrrPhysbaseRegister::default();
            self.variable_mtrrs_phys_mask[i] = MsrIa32MtrrPhysmaskRegister::default();
        }

        self.def_type_msr.set_e(true);
        self.def_type_msr.set_mem_type(system_parameter.default_cache_type as u8);

        self.mtrr_cap_msr.set_vcnt(system_parameter.variable_mtrr_count as u8);
        self.mtrr_cap_msr.set_fix(system_parameter.fixed_mtrr_supported);

        self.cpuid_version_info_edx.set_mtrr(system_parameter.mtrr_supported);
        self.cpuid_vir_phy_address_size_eax.set_physical_address_bits(system_parameter.physical_address_bits);
        if system_parameter.mk_tme_keyid_bits != 0 {
            self.cpuid_extended_feature_flags_ecx.set_tme_en(true);
            self.tme_activate_msr.set_tme_enable(true);
            self.tme_activate_msr.set_mk_tme_keyid_bits(system_parameter.mk_tme_keyid_bits);
        } else {
            self.cpuid_extended_feature_flags_ecx.set_tme_en(false);
            self.tme_activate_msr.set_tme_enable(false);
            self.tme_activate_msr.set_mk_tme_keyid_bits(0);
        }
    }

    pub fn set_pcd_cpu_number_of_reserved_variable_mtrrs(&mut self, count: u32) {
        self.pcd_cpu_number_of_reserved_variable_mtrrs = count;
    }
}

impl HalTrait for MockHal {
    fn save_and_disable_interrupts(&mut self) -> bool {
        let interrupt_state = self.get_interrupt_state();
        self.disable_interrupts();
        interrupt_state
    }

    #[inline(always)]
    fn enable_interrupts(&mut self) {
        self.interrupt_state = true;
    }

    #[inline(always)]
    fn disable_interrupts(&mut self) {
        self.interrupt_state = false;
    }

    fn asm_disable_cache(&mut self) {}

    fn asm_enable_cache(&mut self) {}

    fn set_interrupt_state(&mut self, interrupt_state: bool) {
        if interrupt_state {
            self.enable_interrupts();
        } else {
            self.disable_interrupts();
        }
    }

    #[inline(always)]
    fn get_interrupt_state(&mut self) -> bool {
        self.interrupt_state
    }

    /// Write CR3 register. Also invalidates TLB.
    fn asm_write_cr3(&mut self, value: u64) {
        self.cr3 = value;
    }

    /// Read CR3 register.
    fn asm_read_cr3(&mut self) -> u64 {
        self.cr3
    }

    /// Write CR4 register. Also invalidates TLB.
    #[inline(always)]
    fn asm_write_cr4(&mut self, value: u64) {
        self.cr4 = value;
    }

    /// Read CR4 register.
    #[inline(always)]
    fn asm_read_cr4(&mut self) -> u64 {
        self.cr4
    }

    fn cpu_flush_tlb(&mut self) {}

    fn asm_read_msr64(&mut self, msr_index: u32) -> u64 {
        for i in 0..self.fixed_mtrrs_value.len() {
            if msr_index == M_FIXED_MTRRS_INDEX[i] {
                return self.fixed_mtrrs_value[i];
            }
        }

        if (msr_index >= MSR_IA32_MTRR_PHYSBASE0)
            && (msr_index <= (MSR_IA32_MTRR_PHYSMASK0 + (MTRR_NUMBER_OF_VARIABLE_MTRR as u32 * 2)))
        {
            if msr_index % 2 == 0 {
                let index = ((msr_index - MSR_IA32_MTRR_PHYSBASE0) >> 1) as usize;
                return self.variable_mtrrs_phys_base[index].into();
            } else {
                let index = ((msr_index - MSR_IA32_MTRR_PHYSMASK0) >> 1) as usize;
                return self.variable_mtrrs_phys_mask[index].into();
            }
        }

        if msr_index == MSR_IA32_MTRR_DEF_TYPE {
            return self.def_type_msr.into();
        }

        if msr_index == MSR_IA32_MTRRCAP {
            return self.mtrr_cap_msr.into_bits() as u64;
        }

        if msr_index == MSR_IA32_TME_ACTIVATE {
            return self.tme_activate_msr.into();
        }

        // Should never fall through to here
        assert!(false);
        return 0;
    }

    fn asm_write_msr64(&mut self, msr_index: u32, value: u64) {
        for i in 0..self.fixed_mtrrs_value.len() {
            if msr_index == M_FIXED_MTRRS_INDEX[i] {
                self.fixed_mtrrs_value[i] = value;
                return;
            }
        }

        if (msr_index >= MSR_IA32_MTRR_PHYSBASE0)
            && (msr_index <= (MSR_IA32_MTRR_PHYSMASK0 + (MTRR_NUMBER_OF_VARIABLE_MTRR as u32 * 2)))
        {
            if msr_index % 2 == 0 {
                let index = ((msr_index - MSR_IA32_MTRR_PHYSBASE0) >> 1) as usize;
                self.variable_mtrrs_phys_base[index] = MsrIa32MtrrPhysbaseRegister::from_bits(value);
                return;
            } else {
                let index = ((msr_index - MSR_IA32_MTRR_PHYSMASK0) >> 1) as usize;
                self.variable_mtrrs_phys_mask[index] = MsrIa32MtrrPhysmaskRegister::from_bits(value);
                return;
            }
        }

        if msr_index == MSR_IA32_MTRR_DEF_TYPE {
            let def_type = MsrIa32MtrrDefType::from_bits(value);
            if def_type.fe() {
                assert!(self.mtrr_cap_msr.fix());
            }
            self.def_type_msr = def_type;
            return;
        }

        if msr_index == MSR_IA32_MTRRCAP {
            self.mtrr_cap_msr = MsrIa32MtrrcapRegister::from_bits((value & 0xFFFF_FFFF) as u32);
            return;
        }

        // Should never fall through to here
        assert!(false);
    }

    fn asm_msr_and_then_or_64(&mut self, index: u32, and_data: u64, or_data: u64) -> u64 {
        let currentvalue = self.asm_read_msr64(index);
        let newvalue = (currentvalue & and_data) | or_data;
        self.asm_write_msr64(index, newvalue);
        newvalue
    }

    fn asm_cpuid(&mut self, function: u32) -> CpuidResult {
        self.asm_cpuid_ex(function, 0)
    }

    fn asm_cpuid_ex(&mut self, function: u32, _sub_function: u32) -> CpuidResult {
        const CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS: u32 = 0x07;
        let mut result = CpuidResult { eax: 0, ebx: 0, ecx: 0, edx: 0 };

        match function {
            CPUID_SIGNATURE => {
                result.eax = CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS;
                result
            }
            CPUID_VERSION_INFO => {
                result.edx = self.cpuid_version_info_edx.into();
                result
            }
            CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS => {
                result.ecx = self.cpuid_extended_feature_flags_ecx.into_bits();
                result
            }
            CPUID_EXTENDED_FUNCTION => {
                result.eax = CPUID_VIR_PHY_ADDRESS_SIZE;
                result
            }
            CPUID_VIR_PHY_ADDRESS_SIZE => {
                result.eax = self.cpuid_vir_phy_address_size_eax.into_bits();
                result
            }
            _ => {
                assert!(false);
                result
            }
        }
    }

    fn get_pcd_cpu_number_of_reserved_variable_mtrrs(&self) -> u32 {
        self.pcd_cpu_number_of_reserved_variable_mtrrs
    }
}
