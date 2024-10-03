#[allow(unused_imports)]
use core::arch::asm;
use core::arch::x86_64::CpuidResult;
use core::arch::x86_64::__cpuid;
use core::arch::x86_64::__cpuid_count;

pub trait HalTrait {
    fn save_and_disable_interrupts(&mut self) -> bool;
    fn enable_interrupts(&mut self);
    fn disable_interrupts(&mut self);
    fn asm_disable_cache(&mut self);
    fn asm_enable_cache(&mut self);
    fn set_interrupt_state(&mut self, interrupt_state: bool);
    fn get_interrupt_state(&self) -> bool;
    fn asm_write_cr3(&mut self, value: u64);
    fn asm_read_cr3(&self) -> u64;
    fn asm_write_cr4(&mut self, value: u64);
    fn asm_read_cr4(&self) -> u64;
    fn cpu_flush_tlb(&mut self);
    fn asm_read_msr64(&self, msr: u32) -> u64;
    fn asm_write_msr64(&mut self, msr: u32, value: u64);
    fn asm_msr_and_then_or_64(&mut self, index: u32, and_data: u64, or_data: u64) -> u64;
    fn asm_cpuid(&self, function: u32) -> CpuidResult;
    fn asm_cpuid_ex(&self, function: u32, sub_function: u32) -> CpuidResult;
    fn get_pcd_cpu_number_of_reserved_variable_mtrrs(&self) -> u32;
}

pub struct Hal;

impl Hal {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Hal {
    fn default() -> Self {
        Self::new()
    }
}

impl HalTrait for Hal {
    fn save_and_disable_interrupts(&mut self) -> bool {
        let interrupt_state = self.get_interrupt_state();
        self.disable_interrupts();
        interrupt_state
    }

    #[inline(always)]
    fn enable_interrupts(&mut self) {
        unsafe {
            asm!("sti");
        }
    }

    #[inline(always)]
    fn disable_interrupts(&mut self) {
        unsafe {
            asm!("cli");
        }
    }

    #[inline(always)]
    fn asm_disable_cache(&mut self) {
        unsafe {
            asm!(
                "mov {0}, cr0",
                "bts {0}, 30",  // Set the 30th bit (CD: Cache Disable)
                "btr {0}, 29",  // Clear the 29th bit (NW: Not Write-through)
                "mov cr0, {0}", // Write back the updated value to CR0
                "wbinvd",       // Write back and invalidate cache
                out(reg) _,
                options(nostack)
            );
        }
    }

    #[inline(always)]
    fn asm_enable_cache(&mut self) {
        unsafe {
            asm!(
                "wbinvd",       // Write back and invalidate cache
                "mov {0}, cr0", // Load current CR0 register value
                "btr {0}, 29",  // Clear the 29th bit (NW: Not Write-through)
                "btr {0}, 30",  // Clear the 30th bit (CD: Cache Disable)
                "mov cr0, {0}", // Write the updated value back to CR0
                out(reg) _,
                options(nostack)
            );
        }
    }

    fn set_interrupt_state(&mut self, interrupt_state: bool) {
        if interrupt_state {
            self.enable_interrupts();
        } else {
            self.disable_interrupts();
        }
    }

    #[inline(always)]
    fn get_interrupt_state(&self) -> bool {
        let r: u64;

        unsafe {
            asm!("pushfq; pop {}", out(reg) r, options(nomem, preserves_flags));
        }

        (r >> 9) & 1 == 1
    }

    /// Write CR3 register. Also invalidates TLB.
    fn asm_write_cr3(&mut self, value: u64) {
        unsafe {
            asm!("mov cr3, {}", in(reg) value, options(nostack, preserves_flags));
        }
    }

    /// Read CR3 register.
    fn asm_read_cr3(&self) -> u64 {
        let mut value;

        unsafe {
            asm!("mov {}, cr3", out(reg) value, options(nostack, preserves_flags));
        }

        value
    }

    /// Write CR4 register. Also invalidates TLB.
    #[inline(always)]
    fn asm_write_cr4(&mut self, value: u64) {
        unsafe {
            asm!("mov cr4, {}", in(reg) value, options(nostack, preserves_flags));
        }
    }

    /// Read CR4 register.
    #[inline(always)]
    fn asm_read_cr4(&self) -> u64 {
        let mut value;

        unsafe {
            asm!("mov {}, cr4", out(reg) value, options(nostack, preserves_flags));
        }

        value
    }

    #[inline(always)]
    fn cpu_flush_tlb(&mut self) {
        let value = self.asm_read_cr3();
        self.asm_write_cr3(value);
    }

    fn asm_read_msr64(&self, msr: u32) -> u64 {
        let (mut high, mut low): (u32, u32);
        unsafe {
            asm!(
                "rdmsr",
                in("ecx") msr,
                out("eax") low, out("edx") high,
                options(nomem, nostack, preserves_flags),
            );
        }
        ((high as u64) << 32) | (low as u64)
    }

    fn asm_write_msr64(&mut self, msr: u32, value: u64) {
        let low = value as u32;
        let high = (value >> 32) as u32;
        unsafe {
            asm!(
                "wrmsr",
                in("ecx") msr,
                in("eax") low, in("edx") high,
                options(nostack, preserves_flags),
            );
        }
    }

    fn asm_msr_and_then_or_64(&mut self, index: u32, and_data: u64, or_data: u64) -> u64 {
        let currentvalue = self.asm_read_msr64(index);
        let newvalue = (currentvalue & and_data) | or_data;
        self.asm_write_msr64(index, newvalue);
        newvalue
    }

    fn asm_cpuid(&self, function: u32) -> CpuidResult {
        unsafe { __cpuid(function) }
    }

    fn asm_cpuid_ex(&self, function: u32, sub_function: u32) -> CpuidResult {
        unsafe { __cpuid_count(function, sub_function) }
    }

    fn get_pcd_cpu_number_of_reserved_variable_mtrrs(&self) -> u32 {
        // This is a placeholder value
        0 // Example reserved MTRR number
    }
}
