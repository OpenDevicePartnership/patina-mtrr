#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
extern crate alloc;
pub mod mtrr;
pub mod error;
pub(crate) mod reg;

