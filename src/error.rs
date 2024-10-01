pub type MtrrResult<T> = Result<T, MtrrError>;

#[derive(Debug, PartialEq)]
pub enum MtrrError {
    MtrrNotSupported,
    VariableRangeMtrrExhausted,
    FixedRangeMtrrBaseAddressNotAligned,
    FixedRangeMtrrLengthNotAligned,
    ReturnInvalidParameter,
    ReturnUnsupported,
    ReturnBufferTooSmall,
    ReturnOutOfResources,
    ReturnAlreadyStarted,
}
