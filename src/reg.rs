#[allow(unused_imports)]
use core::arch::asm;

pub(crate) const CR3_PAGE_BASE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000; // 40 bit - lower 12 bits for alignment

/// Write CR3 register. Also invalidates TLB.
pub unsafe fn write_cr3(_value: u64) {
    #[cfg(not(feature = "no-reg-rw"))]
    {
        unsafe {
            asm!("mov cr3, {}", in(reg) _value, options(nostack, preserves_flags));
        }
    }
}

/// Read CR3 register.
pub unsafe fn read_cr3() -> u64 {
    let mut _value = 0u64;

    #[cfg(not(feature = "no-reg-rw"))]
    {
        unsafe {
            asm!("mov {}, cr3", out(reg) _value, options(nostack, preserves_flags));
        }
    }

    _value
}

/// Invalidate the TLB by reloading the CR3 register if the base is currently
/// being used
pub unsafe fn invalidate_tlb(base: u64) {
    let value = base & CR3_PAGE_BASE_ADDRESS_MASK;
    if read_cr3() == value {
        write_cr3(value);
    }
}

pub unsafe fn write_msr(msr: u32, value: u64) {
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

pub unsafe fn read_msr(msr: u32) -> u64 {
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
