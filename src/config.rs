use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Manifest {
    pub services: Vec<ServiceEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServiceEntry {
    pub name: String,
    pub auto_start: bool,
    pub dependencies: Vec<String>,
}

impl Manifest {
    pub const fn new() -> Self {
        Self { services: Vec::new() }
    }
}
