# Introduction

MTRR(Memory Type Range Registers) is described in 7.7 Vol 2 of AMD64
Architecture Programmer's Manual and 12.11 Vol 3A of Intel Software Developers
Manual

# Getting Started

## Public API:
```rust
pub fn create_mtrr_lib() -> MtrrLib;

pub fn is_mtrr_supported(&self) -> bool;

pub fn mtrr_get_all_mtrrs(&self) -> MtrrSettings;

pub fn mtrr_set_all_mtrrs(&mut self, mtrr_setting: &MtrrSettings);

pub fn mtrr_get_memory_attribute(&self, address: u64) -> MtrrMemoryCacheType;

pub fn mtrr_set_memory_attribute(
    &mut self,
    base_address: u64,
    length: u64,
    attribute: MtrrMemoryCacheType,
) -> MtrrResult<()>;

pub fn mtrr_set_memory_attributes(
    &mut self,
    ranges: &[MtrrMemoryRange],
) -> MtrrResult<()>;

pub fn mtrr_get_memory_ranges(
    &self
) -> MtrrResult<Vec<MtrrMemoryRange>>;

pub fn mtrr_debug_print_all_mtrrs(&self);
```

## API usage:
```rust
fn mtrr_lib_usage() {
    // Create MTRR library
    let mut mtrrlib = create_mtrr_lib();

    // Get the current MTRR settings
    let mut mtrr_settings = mtrrlib.mtrr_get_all_mtrrs();

    // Set default mem type to WriteBack and appropriately update the fixed mtrr
    mtrr_settings.mtrr_def_type_reg.set_mem_type(MtrrMemoryCacheType::WriteBack as u8);
    for index in 0..mtrr_settings.fixed.mtrr.len() {
        mtrr_settings.fixed.mtrr[index] = 0x0606060606060606; //WriteBack
    }

    // Set the MTRR settings
    mtrrlib.mtrr_set_all_mtrrs(&mtrr_settings);


    const BASE_128KB: u64 = 0x00020000;
    const BASE_512KB: u64 = 0x00080000;
    const BASE_1MB: u64 = 0x00100000;
    const BASE_4GB: u64 = 0x0000000100000000;

    //
    // Set memory range from 640KB to 1MB to uncacheable
    //
    let status = mtrrlib.mtrr_set_memory_attribute(
        BASE_512KB + BASE_128KB,
        BASE_1MB - (BASE_512KB + BASE_128KB),
        MtrrMemoryCacheType::Uncacheable,
    );
    assert!(status.is_ok());

    //
    // Set the memory range from the start of the 32-bit MMIO area (32-bit PCI
    // MMIO aperture on i440fx, PCIEXBAR on q35) to 4GB as uncacheable.
    //
    let status = mtrrlib.mtrr_set_memory_attribute(0xB0000000, BASE_4GB - 0xB0000000, MtrrMemoryCacheType::Uncacheable);
    assert!(status.is_ok());

    // MTRR Settings:
    // =============
    // MTRR Default Type: 0x00000000000c06
    // Fixed MTRR[00]   : 0x606060606060606
    // Fixed MTRR[01]   : 0x606060606060606
    // Fixed MTRR[02]   : 0x00000000000000
    // Fixed MTRR[03]   : 0x00000000000000
    // Fixed MTRR[04]   : 0x00000000000000
    // Fixed MTRR[05]   : 0x00000000000000
    // Fixed MTRR[06]   : 0x00000000000000
    // Fixed MTRR[07]   : 0x00000000000000
    // Fixed MTRR[08]   : 0x00000000000000
    // Fixed MTRR[09]   : 0x00000000000000
    // Fixed MTRR[10]   : 0x00000000000000
    // Variable MTRR[00]: Base=0x000000c0000000 Mask=0x00003fc0000800
    // Variable MTRR[01]: Base=0x000000b0000000 Mask=0x00003ff0000800
    // Memory Ranges:
    // ====================================
    // WB:0x00000000000000-0x0000000009ffff
    // UC:0x000000000a0000-0x000000000fffff
    // WB:0x00000000100000-0x000000afffffff
    // UC:0x000000b0000000-0x000000ffffffff
    // WB:0x00000100000000-0x00003fffffffff
}

```
