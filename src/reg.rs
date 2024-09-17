#[allow(unused_imports)]
use core::arch::asm;
use core::arch::x86_64::CpuidResult;
use core::arch::x86_64::__cpuid;
use core::arch::x86_64::__cpuid_count;

pub fn save_and_disable_interrupts() -> bool {
    let interrupt_state = get_interrupt_state();
    disable_interrupts();
    interrupt_state
}

#[inline(always)]
fn enable_interrupts() {
    unsafe {
        asm!("sti");
    }
}

#[inline(always)]
fn disable_interrupts() {
    unsafe {
        asm!("cli");
    }
}

#[inline(always)]
pub fn asm_disable_cache() {
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
pub fn asm_enable_cache() {
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

pub fn set_interrupt_state(interrupt_state: bool) {
    if interrupt_state {
        enable_interrupts();
    } else {
        disable_interrupts();
    }
}

#[inline(always)]
pub fn get_interrupt_state() -> bool {
    let r: u64;

    unsafe {
        asm!("pushfq; pop {}", out(reg) r, options(nomem, preserves_flags));
    }

    (r >> 9) & 1 == 1
}

/// Write CR3 register. Also invalidates TLB.
pub fn asm_write_cr3(_value: u64) {
    #[cfg(not(feature = "no-reg-rw"))]
    {
        unsafe {
            asm!("mov cr3, {}", in(reg) _value, options(nostack, preserves_flags));
        }
    }
}

/// Read CR3 register.
pub fn asm_read_cr3() -> u64 {
    let mut _value = 0u64;

    #[cfg(not(feature = "no-reg-rw"))]
    {
        unsafe {
            asm!("mov {}, cr3", out(reg) _value, options(nostack, preserves_flags));
        }
    }

    _value
}

/// Write CR4 register. Also invalidates TLB.
#[inline(always)]
pub fn asm_write_cr4(_value: u64) {
    #[cfg(not(feature = "no-reg-rw"))]
    {
        unsafe {
            asm!("mov cr4, {}", in(reg) _value, options(nostack, preserves_flags));
        }
    }
}

/// Read CR4 register.
#[inline(always)]
pub fn asm_read_cr4() -> u64 {
    let mut _value = 0u64;

    #[cfg(not(feature = "no-reg-rw"))]
    {
        unsafe {
            asm!("mov {}, cr4", out(reg) _value, options(nostack, preserves_flags));
        }
    }

    _value
}

#[inline(always)]
pub fn cpu_flush_tlb() {
    asm_write_cr3(asm_read_cr3());
}

pub fn asm_read_msr64(msr: u32) -> u64 {
    let (mut _high, mut _low): (u32, u32) = (0, 0);
    #[cfg(not(feature = "no-reg-rw"))]
    {
        unsafe {
            asm!(
                "rdmsr",
                in("ecx") msr,
                out("eax") _low, out("edx") _high,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    ((_high as u64) << 32) | (_low as u64)
}

pub fn asm_write_msr64(msr: u32, value: u64) {
    let _low = value as u32;
    let _high = (value >> 32) as u32;
    #[cfg(not(feature = "no-reg-rw"))]
    {
        unsafe {
            asm!(
                "wrmsr",
                in("ecx") msr,
                in("eax") _low, in("edx") _high,
                options(nostack, preserves_flags),
            );
        }
    }
}

pub fn asm_msr_and_then_or_64(index: u32, and_data: u64, or_data: u64) -> u64 {
    let current_value = asm_read_msr64(index);
    let new_value = (current_value & and_data) | or_data;
    asm_write_msr64(index, new_value);
    new_value
}


pub fn asm_cpuid(function: u32) -> CpuidResult {
    unsafe { __cpuid(function) }
}

pub fn asm_cpuid_ex(function: u32, sub_function: u32) -> CpuidResult {
    unsafe { __cpuid_count(function, sub_function) }
}
