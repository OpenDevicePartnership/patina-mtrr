//! Test module declarations and shared test setup for the MTRR library.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0

pub(crate) use config::*;
pub(crate) use mock_hal::MockHal;

mod config;
mod fixtures;
mod mock_hal;
mod mtrr_tests;
mod support;
