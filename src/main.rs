pub mod banner;
pub mod enums;
pub mod json;
pub mod modules;
pub mod utils;

use env_logger::Builder;
use log::{error, info, trace};
use std::error::Error;

// reexport for modules that arent part of the core lib
pub use rusthound_ce::{
    args, objects, ADResults,
    {cache, cache::CacheHandle},
    {ldap, ldap::ldap_search_with_cache},
};

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

    let mut results = match common_args.resume {
        true => {
            // TODO: just continue and call the prepare_results_from_cache function
            info!("Resuming from cache: {}", ldap_cache_path.display());
            let cache = CacheHandle::from_path(ldap_cache_path)?;
            rusthound_ce::prepare_results_from_cache(cache, &common_args, None).await?
        }
        false => {
            if common_args.cache {
                info!("Using cache for LDAP search: {}", ldap_cache_path.display());
                let (cache, total_cached) = ldap_search_with_cache(
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
                    common_args.cache_buffer_size,
                )
                .await?;
                info!("Found {total_cached} LDAP objects",);
                rusthound_ce::prepare_results_from_cache(cache, &common_args, Some(total_cached))
                    .await?
            } else {
                let result = rusthound_ce::ldap_search(
                    common_args.ldaps,
                    common_args.ip.as_deref(),
                    common_args.port,
                    &common_args.domain,
                    &common_args.ldapfqdn,
                    common_args.username.as_deref(),
                    common_args.password.as_deref(),
                    common_args.kerberos,
                    &common_args.ldap_filter,
                )
                .await?;
                rusthound_ce::prepare_results(result, &common_args).await?
            }
        }
    };

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
