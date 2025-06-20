pub mod banner;
pub mod enums;
pub mod json;
pub mod modules;
pub mod utils;

use env_logger::Builder;
use log::{error, info, trace};
use rusthound_ce::ldap::ldap_search_with_cache;
use rusthound_ce::ldap::LdapSearchEntry;
use std::error::Error;
use std::io::BufReader;

pub use rusthound_ce::args;
pub use rusthound_ce::io;
pub use rusthound_ce::ldap;
pub use rusthound_ce::objects;

#[cfg(feature = "noargs")]
use rusthound_ce::args::auto_args;
#[cfg(not(feature = "noargs"))]
use rusthound_ce::args::{extract_args, Options};

use banner::{print_banner, print_end_banner};
// use ldap::ldap_search;
use modules::run_modules;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Main of RustHound
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    // Banner
    print_banner();

    // Get args
    #[cfg(not(feature = "noargs"))]
    let common_args: Options = extract_args();
    #[cfg(feature = "noargs")]
    let common_args = auto_args();

    // Build logger
    Builder::new()
        .filter(Some("rusthound"), common_args.verbose)
        .filter_level(log::LevelFilter::Error)
        .init();

    // Get verbose level
    info!("Verbosity level: {:?}", common_args.verbose);
    info!("Collection method: {:?}", common_args.collection_method);

    let ldap_cache_path =
        std::path::PathBuf::from(format!(".rusthound-cache/{}", common_args.domain))
            .join("searched_objects.bin");

    let mut total_objects = None;
    let result: Vec<ldap3::SearchEntry> = match common_args.resume {
        true => {
            info!("Resuming from cache: {}", ldap_cache_path.display());
            let data: Vec<LdapSearchEntry> = bincode::decode_from_reader(
                BufReader::new(std::fs::File::open(&ldap_cache_path)?),
                bincode::config::standard(),
            )?;
            data.into_iter().map(Into::into).collect::<Vec<_>>()
        }
        false => {
            // LDAP request to get all informations in result
            let (_, total_cached) = ldap_search_with_cache(
                common_args.ldaps,
                common_args.ip.as_deref(),
                common_args.port,
                &common_args.domain,
                &common_args.ldapfqdn,
                common_args.username.as_deref(),
                common_args.password.as_deref(),
                common_args.kerberos,
                &common_args.ldap_filter,
                &ldap_cache_path,
            )
            .await?;
            total_objects = Some(total_cached);

            log::debug!("Loading LDAP cache from: {}", ldap_cache_path.display());
            let data: Vec<LdapSearchEntry> = crate::io::bincode_load_streaming(
                &ldap_cache_path,
                // bincode::config::standard(),
            )?;
            data.into_iter().map(Into::into).collect::<Vec<_>>()
        }
    };

    info!("Found {} LDAP objects", result.len());
    let memory_usage: usize = result
        .iter()
        .map(|entry| {
            std::mem::size_of::<ldap3::SearchEntry>()
                + entry.dn.len()
                + entry
                    .attrs
                    .iter()
                    .map(|(key, values)| key.len() + values.iter().map(|v| v.len()).sum::<usize>())
                    .sum::<usize>()
        })
        .sum();
    info!("Memory usage for LDAP entries: {} bytes", memory_usage);

    let mut results =
        rusthound_ce::prepare_results_from_cache(ldap_cache_path, &common_args, total_objects)
            .await?;

    // Running modules
    run_modules(
        &common_args,
        &mut results.mappings.fqdn_ip,
        results.computers.as_mut_slice(),
    )
    .await?;

    // Add all in json files
    match rusthound_ce::api::export_results(&common_args, results) {
        Ok(_res) => trace!("Making json/zip files finished!"),
        Err(err) => error!("Error. Reason: {err}"),
    }

    // End banner
    print_end_banner();
    Ok(())
}
