
MTRR(Memory Type Range Registers) is described in 7.7 Vol 2 of AMD64 Architecture
Programmer's Manual.

# API
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
      &self,
      ranges: &mut [MtrrMemoryRange],
      range_count: Option<&mut usize>,
   ) -> MtrrResult<()>;

   pub fn mtrr_debug_print_all_mtrrs(&self);
```

