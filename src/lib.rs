#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
extern crate alloc;
pub mod mtrr;
pub mod structs;
pub mod utils;
pub mod error;
pub mod edk_error;

pub(crate) mod hal;

