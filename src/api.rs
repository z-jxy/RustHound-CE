use std::collections::HashMap;

use ldap3::SearchEntry;

#[derive(Default)]
pub struct DomainMappings {
    /// DN to SID
    pub dn_sid: HashMap<String, String>,
    ///  DN to Type
    pub sid_type: HashMap<String, String>,
    /// FQDN to SID
    pub fqdn_sid: HashMap<String, String>,
    /// fqdn to an ip address
    pub fqdn_ip: HashMap<String, String>,
}

use crate::{
    args::Options,
    cache::CacheHandle,
    json::{
        checker::check_all_result,
        parser::{parse_result_type_from_cache, parse_result_type_from_mem},
    },
    objects::{
        aiaca::AIACA, certtemplate::CertTemplate, computer::Computer, container::Container,
        domain::Domain, enterpriseca::EnterpriseCA, fsp::Fsp, gpo::Gpo, group::Group,
        inssuancepolicie::IssuancePolicie, ntauthstore::NtAuthStore, ou::Ou, rootca::RootCA,
        trust::Trust, user::User,
    },
};

#[derive(Default)]
pub struct ADResults {
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    pub computers: Vec<Computer>,
    pub ous: Vec<Ou>,
    pub domains: Vec<Domain>,
    pub gpos: Vec<Gpo>,
    pub fsps: Vec<Fsp>,
    pub containers: Vec<Container>,
    pub trusts: Vec<Trust>,
    pub ntauthstores: Vec<NtAuthStore>,
    pub aiacas: Vec<AIACA>,
    pub rootcas: Vec<RootCA>,
    pub enterprisecas: Vec<EnterpriseCA>,
    pub certtemplates: Vec<CertTemplate>,
    pub issuancepolicies: Vec<IssuancePolicie>,

    pub mappings: DomainMappings,
}

impl ADResults {
    pub fn new() -> Self {
        Self::default()
    }
}

pub async fn prepare_results(
    result: Vec<SearchEntry>,
    options: &Options,
) -> Result<ADResults, Box<dyn std::error::Error>> {
    let mut ad_results = parse_result_type_from_mem(options, result)?;

    // Functions to replace and add missing values
    check_all_result(
        options,
        &mut ad_results.users,
        &mut ad_results.groups,
        &mut ad_results.computers,
        &mut ad_results.ous,
        &mut ad_results.domains,
        &mut ad_results.gpos,
        &mut ad_results.fsps,
        &mut ad_results.containers,
        &mut ad_results.trusts,
        &mut ad_results.ntauthstores,
        &mut ad_results.aiacas,
        &mut ad_results.rootcas,
        &mut ad_results.enterprisecas,
        &mut ad_results.certtemplates,
        &mut ad_results.issuancepolicies,
        &ad_results.mappings.dn_sid,
        &ad_results.mappings.sid_type,
        &ad_results.mappings.fqdn_sid,
        &ad_results.mappings.fqdn_ip,
    )?;

    Ok(ad_results)
}

pub async fn prepare_results_from_cache(
    ldap_cache_path: CacheHandle,
    options: &Options,
    total_objects: Option<usize>,
) -> Result<ADResults, Box<dyn std::error::Error>> {
    let mut ad_results = parse_result_type_from_cache(options, ldap_cache_path, total_objects)?;

    // Functions to replace and add missing values
    check_all_result(
        options,
        &mut ad_results.users,
        &mut ad_results.groups,
        &mut ad_results.computers,
        &mut ad_results.ous,
        &mut ad_results.domains,
        &mut ad_results.gpos,
        &mut ad_results.fsps,
        &mut ad_results.containers,
        &mut ad_results.trusts,
        &mut ad_results.ntauthstores,
        &mut ad_results.aiacas,
        &mut ad_results.rootcas,
        &mut ad_results.enterprisecas,
        &mut ad_results.certtemplates,
        &mut ad_results.issuancepolicies,
        &ad_results.mappings.dn_sid,
        &ad_results.mappings.sid_type,
        &ad_results.mappings.fqdn_sid,
        &ad_results.mappings.fqdn_ip,
    )?;

    Ok(ad_results)
}

pub fn export_results(
    common_args: &Options,
    results: ADResults,
) -> Result<(), Box<dyn std::error::Error>> {
    crate::json::maker::make_result(
        common_args,
        results.users,
        results.groups,
        results.computers,
        results.ous,
        results.domains,
        results.gpos,
        results.containers,
        results.ntauthstores,
        results.aiacas,
        results.rootcas,
        results.enterprisecas,
        results.certtemplates,
        results.issuancepolicies,
    )
}
