pub mod buffer;
pub mod iter;
pub use iter::BincodeIterator;

pub use buffer::{jsonl_load, BincodeObjectBuffer, DiskBuffer, JsonLObjectBuffer};

pub struct CacheHandle(pub iter::BincodeFileIterator<crate::ldap::LdapSearchEntry>);

impl CacheHandle {
    /// Create a new cache handle from a file path
    pub fn from_path(file_path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let iter = iter::BincodeFileIterator::from_path(file_path)?;
        Ok(Self(iter))
    }

    /// Create a new cache handle from an existing file
    pub fn from_file(file: std::fs::File) -> Self {
        Self(iter::BincodeFileIterator::from_file(file))
    }
}

impl IntoIterator for CacheHandle {
    type Item = <iter::BincodeFileIterator<crate::ldap::LdapSearchEntry> as Iterator>::Item;
    type IntoIter = iter::BincodeFileIterator<crate::ldap::LdapSearchEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
    }
}
