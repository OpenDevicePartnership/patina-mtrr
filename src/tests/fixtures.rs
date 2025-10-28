//! Test fixtures and builders.
//!
//! Provides reusable test fixtures with deterministic test data generation.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0

use crate::{
    Mtrr,
    mtrr::MtrrLib,
    structs::{MtrrMemoryCacheType, MtrrMemoryRange, MtrrVariableSetting, SIZE_1MB},
    tests::{config::*, mock_hal::MockHal},
};

/// Tracks memory cache type distribution for test patterns.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemoryTypeCounts {
    /// Uncacheable
    pub(crate) uc: u32,
    /// WriteThrough
    pub(crate) wt: u32,
    /// WriteBack
    pub(crate) wb: u32,
    /// WriteProtected
    pub(crate) wp: u32,
    /// WriteCombining
    pub(crate) wc: u32,
}

impl MemoryTypeCounts {
    /// Creates a new memory type count structure with specified type distributions.
    pub(crate) const fn new(uc: u32, wt: u32, wb: u32, wp: u32, wc: u32) -> Self {
        Self { uc, wt, wb, wp, wc }
    }

    /// Returns the total count of all memory type ranges.
    ///
    /// Calculates and returns the sum of all memory type counts, representing
    /// the total number of memory ranges across all cache types.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::MemoryTypeCounts;
    ///
    /// let counts = MemoryTypeCounts::new(2, 3, 4, 1, 2);
    /// assert_eq!(counts.total(), 12);
    /// ```
    pub(crate) const fn total(&self) -> u32 {
        self.uc + self.wt + self.wb + self.wp + self.wc
    }

    /// Checks if all memory type counts are zero.
    ///
    /// Returns true if no memory ranges are specified for any cache type,
    /// indicating an empty memory type distribution.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::MemoryTypeCounts;
    ///
    /// let empty_counts = MemoryTypeCounts::new(0, 0, 0, 0, 0);
    /// assert!(empty_counts.is_empty());
    ///
    /// let non_empty_counts = MemoryTypeCounts::new(1, 0, 0, 0, 0);
    /// assert!(!non_empty_counts.is_empty());
    /// ```
    pub(crate) const fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

/// Deterministic sequence generator for test values.
#[derive(Debug, Clone)]
pub(crate) struct TestSequence {
    index: usize,
}

impl TestSequence {
    /// Creates a new deterministic test sequence starting at the specified index.
    pub(crate) const fn new(index: usize) -> Self {
        Self { index }
    }

    /// Creates a test sequence starting at index zero.
    ///
    /// Convenience method that creates a new test sequence starting from the beginning
    /// of the sequence pattern.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::TestSequence;
    ///
    /// let sequence = TestSequence::starting();
    /// assert_eq!(sequence.index(), 0);
    /// ```
    pub(crate) const fn starting() -> Self {
        Self::new(0)
    }

    /// Generates the next 32-bit test value within the specified range.
    ///
    /// Produces a deterministic 32-bit value between start (inclusive) and limit (exclusive)
    /// from the current sequence position. The sequence automatically advances to the next
    /// position after generating the value.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::TestSequence;
    ///
    /// let mut sequence = TestSequence::starting();
    /// let value = sequence.next_u32(10, 50);
    /// assert!(value >= 10 && value < 50);
    /// ```
    pub(crate) fn next_u32(&mut self, start: u32, limit: u32) -> u32 {
        let value = TEST_VALUES_32[self.index % TEST_VALUES_32.len()];
        self.index = self.index.wrapping_add(1);
        start + (value % (limit - start))
    }

    /// Generates the next 64-bit test value within the specified range.
    ///
    /// Produces a deterministic 64-bit value between start (inclusive) and limit (exclusive)
    /// from the current sequence position. The sequence automatically advances to the next
    /// position after generating the value.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::TestSequence;
    ///
    /// let mut sequence = TestSequence::starting();
    /// let value = sequence.next_u64(1000, 5000);
    /// assert!(value >= 1000 && value < 5000);
    /// ```
    pub(crate) fn next_u64(&mut self, start: u64, limit: u64) -> u64 {
        let value = TEST_VALUES_64[self.index % TEST_VALUES_64.len()];
        self.index = self.index.wrapping_add(1);
        start + (value % (limit - start))
    }

    /// Generates the next memory cache type in the sequence.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::TestSequence;
    /// use patina_mtrr::structs::MtrrMemoryCacheType;
    ///
    /// let mut sequence = TestSequence::starting();
    /// let cache_type = sequence.next_cache_type();
    /// ```
    pub(crate) fn next_cache_type(&mut self) -> MtrrMemoryCacheType {
        let cache_type = CACHE_TYPE_PATTERNS[self.index % CACHE_TYPE_PATTERNS.len()];
        self.index = self.index.wrapping_add(1);
        cache_type
    }

    /// Advances the sequence position by the specified number of steps.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::TestSequence;
    ///
    /// let mut sequence = TestSequence::starting();
    /// assert_eq!(sequence.index(), 0);
    /// sequence.advance(5);
    /// assert_eq!(sequence.index(), 5);
    /// ```
    pub(crate) fn advance(&mut self, steps: usize) {
        self.index = self.index.wrapping_add(steps);
    }

    /// Returns the current position in the sequence.
    ///
    /// Gets the current index position in the deterministic sequence, which can be
    /// used to track progress or reproduce specific sequence states.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::TestSequence;
    ///
    /// let sequence = TestSequence::new(42);
    /// assert_eq!(sequence.index(), 42);
    /// ```
    pub(crate) const fn index(&self) -> usize {
        self.index
    }
}

/// Builder for creating MTRR test fixtures.
#[derive(Debug)]
pub(crate) struct MtrrTestFixture {
    system_parameter: MtrrLibSystemParameter,
    reserved_variable_mtrrs: u32,
    mock_hal: Option<MockHal>,
}

impl MtrrTestFixture {
    /// Creates a new test fixture with default configuration.
    pub(crate) fn new() -> Self {
        Self { system_parameter: DEFAULT_SYSTEM_PARAMETER, reserved_variable_mtrrs: 0, mock_hal: None }
    }

    /// Sets the system parameter configuration for the test fixture.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::{fixtures::MtrrTestFixture, config::MtrrLibSystemParameter};
    /// use patina_mtrr::structs::MtrrMemoryCacheType;
    ///
    /// let params = MtrrLibSystemParameter {
    ///     default_cache_type: MtrrMemoryCacheType::WriteBack,
    ///     physical_address_bits: 40,
    ///     variable_mtrr_count: 10,
    ///     fixed_mtrr_supported: true,
    ///     mtrr_supported: true,
    ///     mk_tme_keyid_bits: 0,
    /// };
    /// let fixture = MtrrTestFixture::new().with_system_parameter(params);
    /// ```
    pub(crate) fn with_system_parameter(mut self, parameter: MtrrLibSystemParameter) -> Self {
        self.system_parameter = parameter;
        self
    }

    /// Sets the number of variable MTRRs to reserve for system use.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::MtrrTestFixture;
    ///
    /// let fixture = MtrrTestFixture::new().with_reserved_variable_mtrrs(2);
    /// ```
    pub(crate) fn with_reserved_variable_mtrrs(mut self, count: u32) -> Self {
        self.reserved_variable_mtrrs = count;
        self
    }

    /// Sets a pre-configured MockHal instance for the test fixture.
    ///
    /// Allows using a custom-configured MockHal instance instead of creating
    /// a new one based on system parameters. This is useful when specific
    /// register states or behaviors are needed for testing.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::{fixtures::MtrrTestFixture, mock_hal::MockHal};
    ///
    /// let mut custom_hal = MockHal::new();
    /// // Configure custom_hal as needed...
    /// let fixture = MtrrTestFixture::new().with_mock_hal(custom_hal);
    /// ```
    pub(crate) fn with_mock_hal(mut self, hal: MockHal) -> Self {
        self.mock_hal = Some(hal);
        self
    }

    /// Creates a mock HAL instance configured with the current system parameters.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::MtrrTestFixture;
    ///
    /// let fixture = MtrrTestFixture::new();
    /// let mock_hal = fixture.create_mock_hal();
    /// ```
    pub(crate) fn create_mock_hal(&self) -> MockHal {
        if let Some(hal) = &self.mock_hal {
            hal.clone()
        } else {
            let mut hal = MockHal::new();
            hal.initialize_mtrr_regs(&self.system_parameter);
            hal
        }
    }

    /// Creates an MTRR library instance configured for testing.
    ///
    /// Instantiates an MTRR library using the configured mock HAL and system parameters.
    /// This provides a complete MTRR library setup ready for testing various MTRR
    /// operations and scenarios.
    pub(crate) fn create_mtrr_lib(&self) -> MtrrLib<MockHal> {
        let hal = self.create_mock_hal();
        MtrrLib::new(hal, self.reserved_variable_mtrrs)
    }

    /// Gets a reference to the current system parameter configuration.
    ///
    /// Returns a reference to the system parameters that will be used to configure
    /// the mock hardware environment. This is useful for inspecting the current
    /// configuration or using it to set up related test components.
    pub(crate) fn system_parameter(&self) -> &MtrrLibSystemParameter {
        &self.system_parameter
    }

    /// Creates a test fixture with MTRR support completely disabled.
    ///
    /// Convenience constructor that sets up a test environment where MTRR support
    /// is not available. This is useful for testing code paths that handle systems
    /// without MTRR capabilities.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::MtrrTestFixture;
    ///
    /// let fixture = MtrrTestFixture::no_mtrr_support();
    /// let mtrr_lib = fixture.create_mtrr_lib();
    /// ```
    pub(crate) fn no_mtrr_support() -> Self {
        Self::new().with_system_parameter(SystemParameterBuilder::no_mtrr_support().build())
    }

    /// Creates a test fixture with fixed MTRR support disabled.
    ///
    /// Convenience constructor that sets up a test environment where variable MTRRs
    /// are supported but fixed MTRRs are not available. This simulates certain
    /// hardware configurations or virtualized environments.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::MtrrTestFixture;
    ///
    /// let fixture = MtrrTestFixture::no_fixed_mtrr_support();
    /// let mtrr_lib = fixture.create_mtrr_lib();
    /// ```
    pub(crate) fn no_fixed_mtrr_support() -> Self {
        Self::new().with_system_parameter(SystemParameterBuilder::no_fixed_mtrr_support().build())
    }

    /// Configures the fixture using a custom configuration function.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::MtrrTestFixture;
    /// use patina_mtrr::structs::MtrrMemoryCacheType;
    ///
    /// let fixture = MtrrTestFixture::new().with_config(|builder| {
    ///     builder
    ///         .with_physical_address_bits(48)
    ///         .with_default_cache_type(MtrrMemoryCacheType::WriteBack)
    /// });
    /// ```
    pub(crate) fn with_config<F>(mut self, config_fn: F) -> Self
    where
        F: FnOnce(SystemParameterBuilder) -> SystemParameterBuilder,
    {
        let builder = SystemParameterBuilder::from(self.system_parameter);
        self.system_parameter = config_fn(builder).build();
        self
    }

    /// Creates an MTRR library instance using the configured parameters.
    ///
    /// Convenience method that creates and returns an MTRR library instance.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::MtrrTestFixture;
    ///
    /// let fixture = MtrrTestFixture::new();
    /// let mtrr_lib = fixture.mtrr_lib();
    /// ```
    pub(crate) fn mtrr_lib(&self) -> MtrrLib<MockHal> {
        self.create_mtrr_lib()
    }

    /// Creates a test fixture with pre-configured deterministic fixed MTRR patterns.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::MtrrTestFixture;
    ///
    /// let fixture = MtrrTestFixture::with_deterministic_fixed_mtrrs();
    /// let mtrr_lib = fixture.create_mtrr_lib();
    /// ```
    pub(crate) fn with_deterministic_fixed_mtrrs() -> Self {
        let (hal, _) = create_fixed_mtrr_test_setup();
        Self::new().with_mock_hal(hal)
    }

    /// Returns the expected fixed MTRR settings for pattern validation.
    ///
    /// Useful for validating MTRR operations produce expected results.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::MtrrTestFixture;
    ///
    /// let fixture = MtrrTestFixture::with_deterministic_fixed_mtrrs();
    /// let expected_settings = fixture.get_expected_fixed_mtrr_settings();
    /// ```
    pub(crate) fn get_expected_fixed_mtrr_settings(&self) -> crate::structs::MtrrFixedSettings {
        let (_, expected_settings) = create_fixed_mtrr_test_setup();
        expected_settings
    }

    /// Creates a test fixture with comprehensive MTRR configuration pre-loaded.
    ///
    /// Sets up a test environment with both variable and fixed MTRRs configured,
    /// along with default type register setup.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::MtrrTestFixture;
    ///
    /// let fixture = MtrrTestFixture::with_comprehensive_mtrr_setup();
    /// let mtrr_lib = fixture.create_mtrr_lib();
    /// ```
    pub(crate) fn with_comprehensive_mtrr_setup() -> Self {
        let (hal, _) = create_comprehensive_mtrr_test_setup();
        Self::new().with_mock_hal(hal)
    }

    /// Returns the expected comprehensive MTRR settings for validation.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::MtrrTestFixture;
    ///
    /// let fixture = MtrrTestFixture::with_comprehensive_mtrr_setup();
    /// let expected_settings = fixture.get_expected_comprehensive_mtrr_settings();
    /// ```
    pub(crate) fn get_expected_comprehensive_mtrr_settings(&self) -> crate::structs::MtrrSettings {
        let (_, expected_settings) = create_comprehensive_mtrr_test_setup();
        expected_settings
    }

    /// Creates a system parameter from the current fixture configuration.
    ///
    /// This is useful if a new instance of the system parameter is needed.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::MtrrTestFixture;
    ///
    /// let fixture = MtrrTestFixture::new();
    /// let params = fixture.create_system_parameter();
    /// ```
    pub(crate) fn create_system_parameter(&self) -> MtrrLibSystemParameter {
        self.system_parameter.clone()
    }
}

impl Default for MtrrTestFixture {
    fn default() -> Self {
        Self::new()
    }
}

/// Creates a test setup with deterministic variable MTRR configuration.
///
/// ## Example
///
/// ```
/// use patina_mtrr::tests::fixtures::create_variable_mtrr_test_setup;
///
/// let (mock_hal, expected_settings) = create_variable_mtrr_test_setup();
/// ```
pub(crate) fn create_variable_mtrr_test_setup() -> (MockHal, crate::structs::MtrrSettings) {
    use crate::{
        hal::Hal,
        structs::{MSR_IA32_MTRR_PHYSBASE0, MSR_IA32_MTRR_PHYSMASK0, MtrrSettings},
        tests::support::{DeterministicGenerator, MtrrPairGenerator},
    };

    let system_parameter = DEFAULT_SYSTEM_PARAMETER;
    let mut expected_mtrr_settings = MtrrSettings::default();
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);

    // Generate Variable MTRR BASE/MASK for specified types
    let mut generator = DeterministicGenerator::new(0);
    let mut pair_generator = MtrrPairGenerator::new(0);

    for index in 0..system_parameter.variable_mtrr_count {
        let cache_type = generator.next_cache_type();
        let (pair_opt, _) = pair_generator.generate_pair(system_parameter.physical_address_bits as u32, cache_type);
        if let Some(pair) = pair_opt {
            expected_mtrr_settings.variables.mtrr[index as usize].base = pair.base;
            expected_mtrr_settings.variables.mtrr[index as usize].mask = pair.mask;
            hal.asm_write_msr64(MSR_IA32_MTRR_PHYSBASE0 + (index << 1), pair.base);
            hal.asm_write_msr64(MSR_IA32_MTRR_PHYSMASK0 + (index << 1), pair.mask);
        }
    }

    (hal, expected_mtrr_settings)
}

/// Creates a test setup with deterministic fixed MTRR configuration.
///
/// ## Example
///
/// ```
/// use patina_mtrr::tests::fixtures::create_fixed_mtrr_test_setup;
///
/// let (mock_hal, expected_fixed_settings) = create_fixed_mtrr_test_setup();
/// ```
pub(crate) fn create_fixed_mtrr_test_setup() -> (MockHal, crate::structs::MtrrFixedSettings) {
    use crate::{
        hal::Hal,
        structs::{MTRR_NUMBER_OF_FIXED_MTRR, MtrrFixedSettings},
        tests::{config::FIXED_MTRR_INDICES, support::DeterministicGenerator},
        utils::lshift_u64,
    };

    let system_parameter = DEFAULT_SYSTEM_PARAMETER;
    let mut expected_fixed_settings = MtrrFixedSettings::default();
    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);

    // Generate fixed MTRR patterns
    let mut generator = DeterministicGenerator::new(0);
    for (msr_index, &msr_address) in FIXED_MTRR_INDICES.iter().enumerate().take(MTRR_NUMBER_OF_FIXED_MTRR) {
        let mut msr_value = 0;
        for byte in 0..8 {
            let mem_type = generator.next_cache_type();
            msr_value |= lshift_u64(mem_type as u8 as u64, byte * 8);
        }

        expected_fixed_settings.mtrr[msr_index] = msr_value;
        hal.asm_write_msr64(msr_address, msr_value);
    }

    (hal, expected_fixed_settings)
}

/// Creates a comprehensive test setup with complete MTRR configuration.
///
/// ## Example
///
/// ```
/// use patina_mtrr::tests::fixtures::create_comprehensive_mtrr_test_setup;
///
/// let (mock_hal, expected_settings) = create_comprehensive_mtrr_test_setup();
/// ```
pub(crate) fn create_comprehensive_mtrr_test_setup() -> (MockHal, crate::structs::MtrrSettings) {
    use crate::{
        hal::Hal,
        structs::{
            MSR_IA32_MTRR_DEF_TYPE, MSR_IA32_MTRR_PHYSBASE0, MSR_IA32_MTRR_PHYSMASK0, MsrIa32MtrrDefType, MtrrSettings,
        },
        tests::{
            config::FIXED_MTRR_INDICES,
            support::{DeterministicGenerator, MtrrPairGenerator},
        },
    };

    let system_parameter = DEFAULT_SYSTEM_PARAMETER;
    let mut expected_settings = MtrrSettings {
        mtrr_def_type_reg: MsrIa32MtrrDefType::default().with_e(true).with_fe(system_parameter.fixed_mtrr_supported),
        ..Default::default()
    };

    let mut hal = MockHal::new();
    hal.initialize_mtrr_regs(&system_parameter);

    // Set Default MTRR Type
    hal.asm_write_msr64(MSR_IA32_MTRR_DEF_TYPE, expected_settings.mtrr_def_type_reg.into_bits());

    // Generate Variable MTRR BASE/MASK pairs
    let mut generator = DeterministicGenerator::new(0);
    let mut pair_generator = MtrrPairGenerator::new(0);
    for index in 0..system_parameter.variable_mtrr_count {
        let cache_type = generator.next_cache_type();
        let (pair_opt, _) = pair_generator.generate_pair(system_parameter.physical_address_bits as u32, cache_type);
        if let Some(pair) = pair_opt {
            expected_settings.variables.mtrr[index as usize].base = pair.base;
            expected_settings.variables.mtrr[index as usize].mask = pair.mask;
            hal.asm_write_msr64(MSR_IA32_MTRR_PHYSBASE0 + (index << 1), pair.base);
            hal.asm_write_msr64(MSR_IA32_MTRR_PHYSMASK0 + (index << 1), pair.mask);
        }
    }

    // Set Fixed MTRRs when enabled
    if system_parameter.fixed_mtrr_supported && system_parameter.mtrr_supported {
        for (msr_index, &msr_address) in FIXED_MTRR_INDICES.iter().enumerate() {
            let mut msr_value = 0u64;
            for byte_index in 0..8 {
                msr_value |= (generator.next_cache_type() as u64) << (byte_index * 8);
            }
            expected_settings.fixed.mtrr[msr_index] = msr_value;
            hal.asm_write_msr64(msr_address, msr_value);
        }
    }

    (hal, expected_settings)
}

/// Range generator for creating (deterministic) memory ranges.
#[derive(Debug, Clone)]
pub(crate) struct RangeGenerator {
    sequence: TestSequence,
}

impl RangeGenerator {
    /// Creates a new range generator.
    pub(crate) fn new(sequence: TestSequence) -> Self {
        Self { sequence }
    }

    /// Generates an MTRR variable setting and memory range for the specified cache type.
    ///
    /// Creates a MTRR configuration pair consisting of a variable MTRR setting (base/mask registers)
    /// and the corresponding memory range description. The generated ranges are designed to be
    /// non-overlapping and fit within the physical address space.
    ///
    /// ## Example
    ///
    /// ```
    /// use patina_mtrr::tests::fixtures::{RangeGenerator, TestSequence};
    /// use patina_mtrr::structs::MtrrMemoryCacheType;
    ///
    /// let mut generator = RangeGenerator::new(TestSequence::starting());
    /// let (mtrr_setting, memory_range) = generator.generate_mtrr_pair(
    ///     36,
    ///     MtrrMemoryCacheType::WriteBack
    /// );
    /// ```
    pub(crate) fn generate_mtrr_pair(
        &mut self,
        physical_address_bits: u32,
        cache_type: MtrrMemoryCacheType,
    ) -> (MtrrVariableSetting, MtrrMemoryRange) {
        let max_physical_address = 1u64 << physical_address_bits;

        let (range_base, range_size) = self.get_range_for_cache_type(cache_type);

        let actual_base = if range_base + range_size <= max_physical_address {
            range_base
        } else {
            max_physical_address - range_size
        };

        let phys_base_phy_mask_valid_bits_mask = (max_physical_address - 1) & 0xfffffffffffff000u64;

        use crate::structs::{MsrIa32MtrrPhysbaseRegister, MsrIa32MtrrPhysmaskRegister};

        let mut phys_base = MsrIa32MtrrPhysbaseRegister::from_bits(actual_base & phys_base_phy_mask_valid_bits_mask);
        phys_base.set_mem_type(cache_type as u8);

        let mut phys_mask =
            MsrIa32MtrrPhysmaskRegister::from_bits((!range_size + 1) & phys_base_phy_mask_valid_bits_mask);
        phys_mask.set_v(true);

        let mtrr_pair = MtrrVariableSetting { base: phys_base.into(), mask: phys_mask.into() };

        let memory_range = MtrrMemoryRange { base_address: actual_base, length: range_size, mem_type: cache_type };

        (mtrr_pair, memory_range)
    }

    /// Gets deterministic range parameters based on cache type.
    ///
    /// Generates memory ranges with predictable patterns for different cache types.
    ///
    /// ## Example
    ///
    /// ```rust
    /// let mut generator = RangeGenerator::new(TestSequence::starting());
    /// let (base, size) = generator.get_range_for_cache_type(MtrrMemoryCacheType::WriteBack);
    /// assert!(base >= 0x40000000); // WB ranges start at 1GB+
    /// assert_eq!(size, 0x4000000);  // WB ranges are 64MB
    /// ```
    fn get_range_for_cache_type(&mut self, cache_type: MtrrMemoryCacheType) -> (u64, u64) {
        // Create deterministic but varied ranges
        let seq_offset = (self.sequence.index() % 4) as u64;
        self.sequence.advance(1);

        match cache_type {
            MtrrMemoryCacheType::Uncacheable => {
                // UC ranges in lower memory
                let base = SIZE_1MB as u64 + (seq_offset * 0x1000000); // 1MB + n*16MB
                let size = 0x100000; // 1MB
                (base, size)
            }
            MtrrMemoryCacheType::WriteThrough => {
                // WT ranges in middle memory
                let base = 0x10000000 + (seq_offset * 0x4000000); // 256MB + n*64MB
                let size = 0x2000000; // 32MB
                (base, size)
            }
            MtrrMemoryCacheType::WriteBack => {
                // WB ranges in higher memory
                let base = 0x40000000 + (seq_offset * 0x8000000); // 1GB + n*128MB
                let size = 0x4000000; // 64MB
                (base, size)
            }
            MtrrMemoryCacheType::WriteProtected => {
                // WP ranges in an even higher memory area
                let base = 0xC0000000 + (seq_offset * 0x10000000); // 3GB + n*256MB
                let size = 0x8000000; // 128MB
                (base, size)
            }
            MtrrMemoryCacheType::WriteCombining => {
                // WC ranges in very high memory
                let base = 0x200000000 + (seq_offset * 0x20000000); // 8GB + n*512MB
                let size = 0x10000000; // 256MB
                (base, size)
            }
            MtrrMemoryCacheType::Reserved1 | MtrrMemoryCacheType::Reserved2 | MtrrMemoryCacheType::Invalid => {
                let base = 0x80000000 + (seq_offset * 0x8000000); // 2GB + n*128MB
                let size = 0x1000000; // 16MB
                (base, size)
            }
        }
    }

    /// Generates multiple MTRR ranges ensuring no overlaps between them.
    ///
    /// Creates a collection of memory ranges according to the specified type counts.
    /// Basic types (UC, WT, WB) are generated first without overlap checking,
    /// then WP and WC ranges are generated with overlap validation.
    ///
    /// ## Example
    ///
    /// ```rust
    /// let mut generator = RangeGenerator::new(TestSequence::starting());
    /// let counts = MemoryTypeCounts::new(2, 1, 1, 1, 1); // 2 UC, 1 WT, 1 WB, 1 WP, 1 WC
    /// let ranges = generator.generate_non_overlapping_ranges(48, counts);
    /// assert_eq!(ranges.len(), 6); // Total count matches
    ///
    /// // Verify no overlaps
    /// for (i, range1) in ranges.iter().enumerate() {
    ///     for range2 in ranges.iter().skip(i + 1) {
    ///         let range1_end = range1.base_address + range1.length;
    ///         let range2_end = range2.base_address + range2.length;
    ///         assert!(range1_end <= range2.base_address || range1.base_address >= range2_end);
    ///     }
    /// }
    /// ```
    pub(crate) fn generate_non_overlapping_ranges(
        &mut self,
        physical_address_bits: u32,
        type_counts: MemoryTypeCounts,
    ) -> Vec<MtrrMemoryRange> {
        let mut ranges = Vec::with_capacity(type_counts.total() as usize);

        // Generate basic UC, WT, WB ranges
        for _ in 0..type_counts.uc {
            let (_, range) = self.generate_mtrr_pair(physical_address_bits, MtrrMemoryCacheType::Uncacheable);
            ranges.push(range);
        }

        for _ in 0..type_counts.wt {
            let (_, range) = self.generate_mtrr_pair(physical_address_bits, MtrrMemoryCacheType::WriteThrough);
            ranges.push(range);
        }

        for _ in 0..type_counts.wb {
            let (_, range) = self.generate_mtrr_pair(physical_address_bits, MtrrMemoryCacheType::WriteBack);
            ranges.push(range);
        }

        // Generate WP and WC ranges with overlap checking
        self.generate_non_overlapping_type_ranges(
            physical_address_bits,
            &mut ranges,
            MtrrMemoryCacheType::WriteProtected,
            type_counts.wp,
        );

        self.generate_non_overlapping_type_ranges(
            physical_address_bits,
            &mut ranges,
            MtrrMemoryCacheType::WriteCombining,
            type_counts.wc,
        );

        ranges
    }

    /// Generates ranges of a specific type with no overlaps with existing ranges.
    ///
    /// ## Example
    ///
    /// ```rust
    /// let mut generator = RangeGenerator::new(TestSequence::starting());
    /// let mut existing_ranges = vec![
    ///     MtrrMemoryRange {
    ///         base_address: 0x1000000,
    ///         length: 0x100000,
    ///         mem_type: MtrrMemoryCacheType::Uncacheable,
    ///     }
    /// ];
    ///
    /// generator.generate_non_overlapping_type_ranges(
    ///     48,
    ///     &mut existing_ranges,
    ///     MtrrMemoryCacheType::WriteThrough,
    ///     2
    /// );
    ///
    /// assert_eq!(existing_ranges.len(), 3); // Original + 2 new ranges
    ///
    /// // Verify new ranges don't overlap with existing
    /// let wt_ranges: Vec<_> = existing_ranges.iter()
    ///     .filter(|r| r.mem_type == MtrrMemoryCacheType::WriteThrough)
    ///     .collect();
    /// assert_eq!(wt_ranges.len(), 2);
    /// ```
    fn generate_non_overlapping_type_ranges(
        &mut self,
        physical_address_bits: u32,
        existing_ranges: &mut Vec<MtrrMemoryRange>,
        cache_type: MtrrMemoryCacheType,
        count: u32,
    ) {
        const MAX_ATTEMPTS: u32 = 100;

        let mut generated = 0;
        let mut attempts = 0;

        while generated < count && attempts < MAX_ATTEMPTS {
            let (_, temp_range) = self.generate_mtrr_pair(physical_address_bits, cache_type);

            if !Self::ranges_overlap(&temp_range, existing_ranges) {
                existing_ranges.push(temp_range);
                generated += 1;
            }

            attempts += 1;
        }

        if generated < count {
            // Note: Panicking since this is only used in test code
            panic!(
                "Unable to generate {} non-overlapping {:?} MTRRs after {} attempts",
                count, cache_type, MAX_ATTEMPTS
            );
        }
    }

    /// Checks if a range overlaps with any range in the collection.
    ///
    /// Determines whether a given memory range overlaps with any of the existing
    /// ranges in the provided collection. Two ranges overlap if they share any
    /// common memory addresses.
    ///
    /// ## Example
    ///
    /// ```rust
    /// let test_range = MtrrMemoryRange {
    ///     base_address: 0x2000000,
    ///     length: 0x100000,
    ///     mem_type: MtrrMemoryCacheType::WriteBack,
    /// };
    ///
    /// let existing_ranges = vec![
    ///     MtrrMemoryRange {
    ///         base_address: 0x1000000,
    ///         length: 0x100000,
    ///         mem_type: MtrrMemoryCacheType::Uncacheable,
    ///     },
    ///     MtrrMemoryRange {
    ///         base_address: 0x2500000,
    ///         length: 0x100000,
    ///         mem_type: MtrrMemoryCacheType::WriteThrough,
    ///     },
    /// ];
    ///
    /// assert!(!RangeGenerator::ranges_overlap(&test_range, &existing_ranges));
    ///
    /// // Test overlapping case
    /// let overlapping_range = MtrrMemoryRange {
    ///     base_address: 0x1080000, // Overlaps with first existing range
    ///     length: 0x100000,
    ///     mem_type: MtrrMemoryCacheType::WriteBack,
    /// };
    ///
    /// assert!(RangeGenerator::ranges_overlap(&overlapping_range, &existing_ranges));
    /// ```
    fn ranges_overlap(range: &MtrrMemoryRange, ranges: &[MtrrMemoryRange]) -> bool {
        ranges.iter().any(|existing| {
            let range_end = range.base_address + range.length;
            let existing_end = existing.base_address + existing.length;

            !(range_end <= existing.base_address || range.base_address >= existing_end)
        })
    }
}

/// Each pattern represents a different distribution of MTRR types.
pub(crate) const MEMORY_TYPE_TEST_PATTERNS: [MemoryTypeCounts; 8] = [
    MemoryTypeCounts::new(2, 1, 1, 1, 1), // Relatively balanced
    MemoryTypeCounts::new(1, 2, 2, 0, 1), // More WT/WB
    MemoryTypeCounts::new(3, 1, 1, 1, 2), // More UC/WC
    MemoryTypeCounts::new(0, 0, 6, 0, 0), // WB only
    MemoryTypeCounts::new(4, 0, 0, 0, 0), // UC only
    MemoryTypeCounts::new(1, 1, 2, 2, 2), // Relatively balanced
    MemoryTypeCounts::new(0, 3, 3, 0, 0), // WT/WB only
    MemoryTypeCounts::new(2, 0, 0, 2, 4), // UC/WP/WC mix
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_type_counts() {
        let counts = MemoryTypeCounts::new(1, 2, 3, 4, 5);
        assert_eq!(counts.total(), 15);
        assert!(!counts.is_empty());

        let empty_counts = MemoryTypeCounts::default();
        assert_eq!(empty_counts.total(), 0);
        assert!(empty_counts.is_empty());
    }

    #[test]
    fn test_sequence_generator() {
        let mut seq = TestSequence::starting();

        let val1 = seq.next_u32(0, 100);
        let val2 = seq.next_u32(0, 100);
        assert_ne!(val1, val2);

        let cache_type = seq.next_cache_type();
        assert!(matches!(
            cache_type,
            MtrrMemoryCacheType::Uncacheable
                | MtrrMemoryCacheType::WriteCombining
                | MtrrMemoryCacheType::WriteThrough
                | MtrrMemoryCacheType::WriteProtected
                | MtrrMemoryCacheType::WriteBack
        ));
    }

    #[test]
    fn test_mtrr_test_fixture() {
        let fixture = MtrrTestFixture::new()
            .with_system_parameter(SystemParameterBuilder::new().with_physical_address_bits(48).build())
            .with_reserved_variable_mtrrs(2);

        assert_eq!(fixture.system_parameter().physical_address_bits, 48);

        let mtrr_lib = fixture.create_mtrr_lib();
        assert!(mtrr_lib.is_supported());
    }

    #[test]
    fn test_range_generator() {
        let mut generator = RangeGenerator::new(TestSequence::starting());

        let (_mtrr_pair, memory_range) = generator.generate_mtrr_pair(42, MtrrMemoryCacheType::WriteBack);

        assert_eq!(memory_range.mem_type, MtrrMemoryCacheType::WriteBack);
        assert!(memory_range.length > 0);
        assert!(memory_range.base_address < (1u64 << 42));
    }

    #[test]
    fn test_memory_type_test_patterns() {
        for (index, pattern) in MEMORY_TYPE_TEST_PATTERNS.iter().enumerate() {
            assert!(pattern.total() > 0, "Pattern {} should have at least one memory type", index);
            assert!(pattern.total() <= 12, "Pattern {} exceeds typical MTRR count", index);

            assert!(pattern.uc <= 8, "Pattern {} has too many UC MTRRs", index);
            assert!(pattern.wt <= 8, "Pattern {} has too many WT MTRRs", index);
            assert!(pattern.wb <= 8, "Pattern {} has too many WB MTRRs", index);
            assert!(pattern.wp <= 8, "Pattern {} has too many WP MTRRs", index);
            assert!(pattern.wc <= 8, "Pattern {} has too many WC MTRRs", index);
        }

        assert_eq!(MEMORY_TYPE_TEST_PATTERNS.len(), 8, "Expected 8 test patterns");
    }
}
