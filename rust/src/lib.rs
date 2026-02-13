#![allow(dead_code)]

pub mod config;
pub mod hash160;
pub mod http_client;
pub mod results;
pub mod xpart;
pub mod hunter;

#[cfg(feature = "cuda")]
pub mod cuda;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("config: {0}")]
    Config(String),
    #[error("hash160: {0}")]
    Hash160(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(String),
    #[error("cuda: {0}")]
    Cuda(String),
}
