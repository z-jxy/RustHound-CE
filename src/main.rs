pub mod banner;
pub mod enums;
pub mod json;
pub mod modules;
pub mod utils;

use env_logger::Builder;
use log::{error, info, trace};
use std::error::Error;

pub use rusthound_ce::args;
pub use rusthound_ce::ldap;
pub use rusthound_ce::objects;

#[cfg(feature = "noargs")]
use rusthound_ce::args::auto_args;
#[cfg(not(feature = "noargs"))]
use rusthound_ce::args::{extract_args, Options};

use banner::{print_banner, print_end_banner};
use json::maker::make_result;
use ldap::ldap_search;
use modules::run_modules;

/// Main of RustHound
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
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

    // LDAP request to get all informations in result
    let result = ldap_search(
        common_args.ldaps,
        common_args.ip.as_deref(),
        common_args.port,
        &common_args.domain,
        &common_args.ldapfqdn,
        &common_args.username,
        &common_args.password,
        common_args.kerberos,
        &common_args.ldap_filter,
    )
    .await?;

    let mut results = rusthound_ce::prepare_results(result, &common_args).await?;

    // Running modules
    run_modules(
        &common_args,
        &mut results.fqdn_ip,
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
