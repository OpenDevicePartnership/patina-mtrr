pub type MtrrResult<T> = Result<T, MtrrError>;

#[derive(Debug, PartialEq)]
pub enum MtrrError {
    // // MTRR Disabled
    // MtrrDisabled,

    // // Unaligned Address
    // UnalignedAddress,

    // // Unaligned Memory Range
    // UnalignedMemoryRange,

    // // Above 1MB Memory Range
    // Above1MBMemoryRange,

    // // Invalid memory length
    // InvalidMemoryRange,

    ReturnInvalidParameter,
    ReturnUnsupported,
    ReturnBufferTooSmall,
    ReturnOutOfResources,
    ReturnAlreadyStarted,
}
