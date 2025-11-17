use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use goblin::pe::PE;
use reqwest::blocking::Client;
use windows::core::GUID;

use crate::wrappers::RemoteModule;

#[derive(Debug, Clone)]
pub struct PdbSignature {
    pub guid: GUID,
    pub age: u32,
    pub filename: String,
}

pub struct SymbolLoader {
    client: Client,
    cache_dir: PathBuf,
}

impl SymbolLoader {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::new();
        
        let cache_dir = dirs::data_local_dir()
        .map(|p|
            PathBuf::from(p)
            .join("inja")
            .join("symbols")
        )
        .unwrap_or_else(|| {
            std::env::temp_dir().join("symbols") // Fallback if LOCALAPPDATA isn't set
        });

        fs::create_dir_all(&cache_dir)?;
        println!("Using symbol cache directory: {}", cache_dir.display());

        Ok(Self { client, cache_dir })
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    fn guid_from_signature(&self, signature: &[u8; 16]) -> Result<GUID, Box<dyn std::error::Error>> {
        Ok(GUID::from_values(
            u32::from_le_bytes(signature[0..4].try_into()?),
            u16::from_le_bytes(signature[4..6].try_into()?),
            u16::from_le_bytes(signature[6..8].try_into()?),
            signature[8..16].try_into()?,
        ))
    }

    fn verify_pdb_integrity(
        &self,
        pdb_path: &Path,
        expected_pdb_sig: &PdbSignature,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let data = fs::read(pdb_path)?;

        if data.len() < 24 || &data[0..4] != b"RSDS" {
            return Ok(false);
        }

        let guid_bytes: [u8; 16] = data[4..20].try_into()?;
        let guid = self.guid_from_signature(&guid_bytes)?;

        let age = u32::from_le_bytes(data[20..24].try_into()?);

        Ok(guid == expected_pdb_sig.guid && age == expected_pdb_sig.age)
    }

    pub fn ensure_pdb_cached(
        &self,
        module: &RemoteModule,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let module_path_str = module.path();
        let file_data = fs::read(module_path_str)?;
        let pdb_sig = self.extract_pdb_signature(&file_data)?;

        let guid_str_upper = self.format_guid_for_url(&pdb_sig.guid);
        let pdb_cache_subdir = self.cache_dir
            .join(&pdb_sig.filename)
            .join(format!("{}{}", guid_str_upper, pdb_sig.age));
        let pdb_cache_filepath = pdb_cache_subdir.join(&pdb_sig.filename);

        if pdb_cache_filepath.exists() {
            if let Ok(true) = self.verify_pdb_integrity(&pdb_cache_filepath, &pdb_sig) {
                return Ok(());
            }
            
            // remove outdated/invalid
            let _ = fs::remove_file(&pdb_cache_filepath);
        }

        let url = format!(
            "https://msdl.microsoft.com/download/symbols/{}/{}{}/{}",
            pdb_sig.filename,
            guid_str_upper,
            pdb_sig.age,
            pdb_sig.filename
        );

        let response = self.client.get(&url).send()?;
        if !response.status().is_success() {
            return Err(format!("Download failed: Status {}", response.status()).into());
        }

        fs::create_dir_all(&pdb_cache_subdir)?;
        let mut file = fs::File::create(&pdb_cache_filepath)?;
        let content = response.bytes()?;
        file.write_all(&content)?;
        
        Ok(())
    }

    fn extract_pdb_signature(
        &self,
        module_data: &[u8],
    ) -> Result<PdbSignature, Box<dyn std::error::Error>> {
        let pe = PE::parse(module_data)?;
        let debug_data = pe.debug_data
            .ok_or("No debug data found in PE")?;

        let cv_info = debug_data.codeview_pdb70_debug_info
            .ok_or("No CodeView PDB 7.0 debug info found in PE")?;

        let guid_bytes = cv_info.signature;
        let guid = self.guid_from_signature(&guid_bytes)?;

        let age = cv_info.age;

        let filename_bytes = cv_info.filename;
        let name_len = filename_bytes.iter().position(|&b| b == 0).unwrap_or(filename_bytes.len());
        let pdb_path = std::str::from_utf8(&filename_bytes[..name_len])?;
        let pdb_filename = Path::new(pdb_path)
            .file_name()
            .ok_or("Invalid PDB path in debug info")?
            .to_string_lossy()
            .to_string();

        Ok(PdbSignature { guid, age, filename: pdb_filename })
    }

    fn format_guid_for_url(&self, guid: &GUID) -> String {
        let data4_hex: String = guid.data4.iter().map(|b| format!("{:02X}", b)).collect();
        format!(
            "{:08X}{:04X}{:04X}{}",
            guid.data1,
            guid.data2,
            guid.data3,
            data4_hex
        )
    }
}