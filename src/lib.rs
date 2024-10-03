// #![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
extern crate alloc;
mod error;
pub mod mtrr;
pub mod structs;
mod utils;

mod hal;

#[cfg(test)]
mod tests;
