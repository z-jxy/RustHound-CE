//! <p align="center">
//!     <picture>
//!         <img src="https://github.com/g0h4n/RustHound-CE/raw/main/img/rusthoundce-transparent-dark-theme.png" alt="rusthound-ce logo" width='250' />
//!     </picture>
//! </p>
//! <hr />
//!
//! RustHound-CE is a cross-platform and cross-compiled BloodHound collector tool written in Rust, making it compatible with Linux, Windows, and macOS. It therefore generates all the JSON files that can be analyzed by BloodHound Community Edition. This version is only compatible with [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound). The version compatible with [BloodHound Legacy](https://github.com/BloodHoundAD/BloodHound) can be found on [NeverHack's github](https://github.com/NH-RED-TEAM/RustHound).
//!
//!
//! You can either run the binary:
//! ```ignore
//! ---------------------------------------------------
//! Initializing RustHound-CE at 13:37:00 UTC on 01/12/23
//! Powered by g0h4n from OpenCyber | NH-RED-TEAM
//! ---------------------------------------------------
//!
//! RustHound-CE
//! g0h4n https://twitter.com/g0h4n_0
//! Active Directory data collector for BloodHound.
//!
//! Usage: rusthound [OPTIONS] --domain <domain>
//!
//! Options:
//!   -v...          Set the level of verbosity
//!   -h, --help     Print help
//!   -V, --version  Print version
//!
//! REQUIRED VALUES:
//!   -d, --domain <domain>  Domain name like: DOMAIN.LOCAL
//!
//! OPTIONAL VALUES:
//!   -u, --ldapusername <ldapusername>  LDAP username, like: user@domain.local
//!   -p, --ldappassword <ldappassword>  LDAP password
//!   -f, --ldapfqdn <ldapfqdn>          Domain Controller FQDN like: DC01.DOMAIN.LOCAL or just DC01
//!   -i, --ldapip <ldapip>              Domain Controller IP address like: 192.168.1.10
//!   -P, --ldapport <ldapport>          LDAP port [default: 389]
//!   -n, --name-server <name-server>    Alternative IP address name server to use for DNS queries
//!   -o, --output <output>              Output directory where you would like to save JSON files [default: ./]
//!
//! OPTIONAL FLAGS:
//!   -c, --collectionmethod [<COLLECTIONMETHOD>]
//!           Which information to collect. Supported: All (LDAP,SMB,HTTP requests), DCOnly (no computer connections, only LDAP requests). (default: All) [possible values: All, DCOnly]
//!       --ldaps
//!           Force LDAPS using for request like: ldaps://DOMAIN.LOCAL/
//!   -k, --kerberos
//!           Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters for Linux.
//!       --dns-tcp
//!           Use TCP instead of UDP for DNS queries
//!       --dc-only
//!           Collects data only from the domain controller. Will not try to retrieve CA security/configuration or check for Web Enrollment
//!   -z, --zip
//!           Compress the JSON files into a zip archive
//!
//! OPTIONAL MODULES:
//!       --fqdn-resolver  Use fqdn-resolver module to get computers IP address
//! ```
//!
//! Or build your own using the ldap_search() function:
//!
//! ```ignore
//! # use rusthound::ldap::ldap_search;
//! # let ldaps = true;
//! # let ip = "127.0.0.1".to_owned();
//! # let port = 676
//! # let domain = "DOMAIN".to_owned()
//! # let ldapfqdn = "domain.com".to_owned()
//! # let username = "user".to_owned()
//! # let password = "pwd".to_owned()
//! # let kerberos= false;
//! let result = ldap_search(
//!     &ldaps,
//!     &Some(ip),
//!     &Some(port),
//!     &domain,
//!     &ldapfqdn,
//!     &username,
//!     &password,
//!     kerberos,
//! );
//! ```
//!
pub mod args;
pub mod banner;
pub mod ldap;
pub mod utils;

pub mod enums;
pub mod json;
pub mod objects;

pub mod api;

pub mod io;

extern crate bitflags;
extern crate chrono;
extern crate regex;

// Reimport key functions and structure
#[doc(inline)]
pub use ldap::ldap_search;
#[doc(inline)]
pub use ldap3::SearchEntry;

pub use api::export_results;
pub use api::prepare_results;
