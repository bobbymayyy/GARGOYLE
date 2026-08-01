#![forbid(unsafe_code)]

pub mod collectors;
pub mod config;
pub mod event;
pub mod fingerprint;
pub mod metrics;
pub mod output;
pub mod platform;
pub mod policy;
pub mod runtime;
pub mod util;

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type Result<T> = std::result::Result<T, BoxError>;
