pub mod buffer;
pub mod iter;
pub use iter::BincodeIterator;

pub use buffer::{BincodeObjectBuffer, Storage};

use crate::ldap::LdapSearchEntry;
pub use iter::BincodeFileIterator;

pub struct CacheHandle(pub BincodeFileIterator<LdapSearchEntry>);

impl CacheHandle {
    /// Create a new cache handle from a file path
    pub fn from_path(file_path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let iter = BincodeFileIterator::from_path(file_path)?;
        Ok(Self(iter))
    }

    /// Create a new cache handle from an existing file
    pub fn from_file(file: std::fs::File) -> Self {
        Self(BincodeFileIterator::from_file(file))
    }
}

impl IntoIterator for CacheHandle {
    type Item = <BincodeFileIterator<LdapSearchEntry> as Iterator>::Item;
    type IntoIter = BincodeFileIterator<LdapSearchEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
    }
}
