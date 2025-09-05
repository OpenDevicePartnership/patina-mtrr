//! Error types and result aliases for the MTRR library.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
pub type MtrrResult<T> = Result<T, MtrrError>;

/// MTRR error types
#[derive(Debug, PartialEq)]
pub enum MtrrError {
    /// MTRR not supported
    MtrrNotSupported,
    /// The number of variable mtrr required to program the ranges are exhausted
    VariableRangeMtrrExhausted,
    /// The address not aligned
    FixedRangeMtrrBaseAddressNotAligned,
    /// The length not aligned
    FixedRangeMtrrLengthNotAligned,
    /// Invalid parameter
    InvalidParameter,
    /// Internal error
    BufferTooSmall,
    /// Internal error
    OutOfResources,
    /// Internal error
    AlreadyStarted,
}
