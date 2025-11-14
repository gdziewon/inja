use std::fs::File;
use std::io::{self, Read, Error, ErrorKind};
use std::path::Path;
use goblin::pe::{self, PE};

#[derive(Debug)]
pub struct PeImage {
    pub raw: Vec<u8>,
}

impl PeImage {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::new(ErrorKind::NotFound, "File not found"));
        }
        
        let mut raw = Vec::new();
        File::open(path)?.read_to_end(&mut raw)?;
        Ok(Self { raw })
    }

    pub fn parse(&self) -> Result<PE, Error> {
        PE::parse(&self.raw).map_err(
            |e| Error::new(ErrorKind::InvalidData, format!("PE parse failed: {e}"))
        )
    }
}