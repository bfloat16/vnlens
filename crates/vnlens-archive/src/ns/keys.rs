//! User-owned key files, never bundled assets. Names follow ExternalKeyReader.
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use vnlens_core::{Error, Result, Secret};
use vnlens_crypto::cipher::aes::decrypt_block128;

#[derive(Clone, Default)]
pub struct Keys {
    values: BTreeMap<String, Secret>,
    directory: PathBuf,
}

#[cfg(test)]
#[path = "../../tests/ns/keys.rs"]
mod tests;

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

impl Keys {
    /// Imports the encrypted title key from a common signed ES ticket. RSA
    /// personalized title-key blocks require the device's own key material.
    /// Signature types determine the signed body's offset; keys stay in memory.
    pub(super) fn ticket(&mut self, source: &dyn vnlens_io::ReadAt) -> Result<()> {
        use vnlens_io::BinaryReader;
        let signature = source.read_at(0, 4)?;
        let offset = match BinaryReader::u32_le(&signature) {
            0x10000 | 0x10003 => 0x240,
            0x10001 | 0x10004 => 0x140,
            0x10002 | 0x10005 => 0x80,
            _ => return Err(super::corrupt(0, "Invalid ES ticket signature type")),
        };
        let body = source.read_at(offset, 0x170)?;
        if body[0x141] != 0 {
            return Ok(());
        }
        let id = body[0x160..0x170]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let value = &body[0x40..0x50];
        if self.values.get(&id).is_some_and(|key| key.bytes() != value) {
            return Err(super::corrupt(
                offset + 0x40,
                "Conflicting encrypted title keys for ticket rights ID",
            ));
        }
        self.values.insert(id, Secret::new(value));
        Ok(())
    }
    /// Loads only user-provided keys from the platform's home directory.
    /// Missing files/keys report their destination without printing values.
    pub fn load_user() -> Result<Self> {
        let home = std::env::home_dir().ok_or_else(|| Error::UnknownScheme(Some(
            "Cannot locate the user home directory; provide your own NS keys in ~/.switch/prod.keys".into()
        )))?;
        Self::load(&home.join(".switch"))
    }

    pub fn load(directory: &Path) -> Result<Self> {
        let mut keys = Self {
            directory: directory.into(),
            ..Self::default()
        };
        keys.read_file("prod.keys", false)?;
        keys.read_file("title.keys", true)?;
        Ok(keys)
    }

    fn missing(&self, key: &str) -> Error {
        Error::UnknownScheme(Some(format!(
            "Missing NS key {key}; obtain your own keys and place prod.keys (and title.keys for rights-managed content) in {}. Keys are not distributed with vnlens",
            self.directory.display()
        )))
    }

    fn read_file(&mut self, filename: &str, optional: bool) -> Result<()> {
        let path = self.directory.join(filename);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if optional {
                    return Ok(());
                }
                return Err(self.missing(filename));
            }
            Err(error) => return Err(error.into()),
        };
        for (line_number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                super::corrupt(
                    line_number as u64 + 1,
                    format!("Invalid NS key file syntax in {}", path.display()),
                )
            })?;
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();
            let mut bytes = Vec::new();
            if !value.len().is_multiple_of(2) || !value.is_ascii() {
                return Err(super::corrupt(
                    line_number as u64 + 1,
                    "Invalid NS key encoding",
                ));
            }
            for pair in value.as_bytes().as_chunks::<2>().0 {
                let digit = |v: u8| (v as char).to_digit(16).map(|d| d as u8);
                let (Some(high), Some(low)) = (digit(pair[0]), digit(pair[1])) else {
                    return Err(super::corrupt(
                        line_number as u64 + 1,
                        "Invalid NS key encoding",
                    ));
                };
                bytes.push(high * 16 + low);
            }
            self.values.insert(key, Secret::new(bytes));
        }
        Ok(())
    }

    pub(super) fn get<const N: usize>(&self, key: &str) -> Result<[u8; N]> {
        let value = self.values.get(key).ok_or_else(|| self.missing(key))?;
        value.bytes().try_into().map_err(|_| {
            Error::UnknownScheme(Some(format!(
                "NS key {key} has the wrong size; replace your key file in {}",
                self.directory.display()
            )))
        })
    }

    pub(super) fn area_key(&self, generation: u8, index: u8) -> Result<[u8; 16]> {
        let kind = match index {
            0 => "application",
            1 => "ocean",
            2 => "system",
            _ => return Err(super::corrupt(0x207, "Invalid NCA key area index")),
        };
        let revision = generation.saturating_sub(1);
        let name = format!("key_area_key_{kind}_{revision:02x}");
        if self.values.contains_key(&name) {
            return self.get(&name);
        }
        // KeyDerivation.GenerateKek: master -> KEK seed -> source -> key seed.
        let master = self.get(&format!("master_key_{revision:02x}"))?;
        let mut kek = self.get("aes_kek_generation_source")?;
        decrypt_block128(&master, &mut kek);
        let mut source = self.get(&format!("key_area_key_{kind}_source"))?;
        decrypt_block128(&kek, &mut source);
        let mut result = self.get("aes_key_generation_source")?;
        decrypt_block128(&source, &mut result);
        Ok(result)
    }

    pub(super) fn title_key(&self, generation: u8, rights: &[u8]) -> Result<[u8; 16]> {
        use std::fmt::Write;
        let mut id = String::new();
        for byte in rights {
            let _ = write!(id, "{byte:02x}");
        }
        let mut title = self.get(&id)?;
        let revision = generation.saturating_sub(1);
        let name = format!("titlekek_{revision:02x}");
        let kek = if self.values.contains_key(&name) {
            self.get(&name)?
        } else {
            let master = self.get(&format!("master_key_{revision:02x}"))?;
            let mut source = self.get("titlekek_source")?;
            decrypt_block128(&master, &mut source);
            source
        };
        decrypt_block128(&kek, &mut title);
        Ok(title)
    }
}
