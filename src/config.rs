use alloc::string::String;
use alloc::vec::Vec;

pub struct Manifest {
    pub services: Vec<ServiceEntry>,
}

pub struct ServiceEntry {
    pub name: String,
    pub path: String,
    pub auto_start: bool,
    pub dependencies: Vec<String>,
}

pub fn load() -> Manifest {
    unimplemented!()
}
