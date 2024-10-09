pub type MtrrResult<T> = Result<T, MtrrError>;

#[derive(Debug, PartialEq)]
pub enum MtrrError {
    MtrrNotSupported,
    VariableRangeMtrrExhausted,
    FixedRangeMtrrBaseAddressNotAligned,
    FixedRangeMtrrLengthNotAligned,
    InvalidParameter,
    Unsupported,
    BufferTooSmall,
    OutOfResources,
    AlreadyStarted,
}
