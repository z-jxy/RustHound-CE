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
    cache::{jsonl_load, CacheHandle},
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
pub struct Results {
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

pub async fn prepare_results(
    result: Vec<SearchEntry>,
    options: &Options,
) -> Result<Results, Box<dyn std::error::Error>> {
    let mut results = Results::default();

    // Analyze object by object
    // Get type and parse it to get values
    parse_result_type_from_mem(
        options,
        result,
        // &mut results.users,
        // &mut results.groups,
        // &mut results.computers,
        // &mut results.ous,
        &mut results.domains,
        // &mut results.gpos,
        &mut results.fsps,
        // &mut results.containers,
        &mut results.trusts,
        &mut results.ntauthstores,
        &mut results.aiacas,
        &mut results.rootcas,
        &mut results.enterprisecas,
        &mut results.certtemplates,
        &mut results.issuancepolicies,
        &mut results.mappings.dn_sid,
        &mut results.mappings.sid_type,
        &mut results.mappings.fqdn_sid,
        &mut results.mappings.fqdn_ip,
    )?;

    results.users = jsonl_load(format!(".rusthound-cache/{}/users.jsonl", options.domain))?;
    results.groups = jsonl_load(format!(".rusthound-cache/{}/groups.jsonl", options.domain))?;
    results.computers = jsonl_load(format!(
        ".rusthound-cache/{}/computers.jsonl",
        options.domain
    ))?;
    results.ous = jsonl_load(format!(".rusthound-cache/{}/ous.jsonl", options.domain))?;
    results.gpos = jsonl_load(format!(".rusthound-cache/{}/gpos.jsonl", options.domain))?;
    results.containers = jsonl_load(format!(
        ".rusthound-cache/{}/containers.jsonl",
        options.domain
    ))?;

    // Functions to replace and add missing values
    check_all_result(
        options,
        &mut results.users,
        &mut results.groups,
        &mut results.computers,
        &mut results.ous,
        &mut results.domains,
        &mut results.gpos,
        &mut results.fsps,
        &mut results.containers,
        &mut results.trusts,
        &mut results.ntauthstores,
        &mut results.aiacas,
        &mut results.rootcas,
        &mut results.enterprisecas,
        &mut results.certtemplates,
        &mut results.issuancepolicies,
        &results.mappings.dn_sid,
        &results.mappings.sid_type,
        &results.mappings.fqdn_sid,
        &results.mappings.fqdn_ip,
    )?;

    Ok(results)
}

pub async fn prepare_results_from_cache(
    ldap_cache_path: CacheHandle,
    options: &Options,
    total_objects: Option<usize>,
) -> Result<Results, Box<dyn std::error::Error>> {
    let mut results = Results::default();

    // Analyze object by object
    // Get type and parse it to get values
    parse_result_type_from_cache(
        options,
        ldap_cache_path,
        &mut results.domains,
        &mut results.fsps,
        &mut results.trusts,
        &mut results.ntauthstores,
        &mut results.aiacas,
        &mut results.rootcas,
        &mut results.enterprisecas,
        &mut results.certtemplates,
        &mut results.issuancepolicies,
        &mut results.mappings.dn_sid,
        &mut results.mappings.sid_type,
        &mut results.mappings.fqdn_sid,
        &mut results.mappings.fqdn_ip,
        total_objects,
    )?;

    results.users = jsonl_load(format!(".rusthound-cache/{}/users.jsonl", options.domain))?;
    results.groups = jsonl_load(format!(".rusthound-cache/{}/groups.jsonl", options.domain))?;
    results.computers = jsonl_load(format!(
        ".rusthound-cache/{}/computers.jsonl",
        options.domain
    ))?;
    results.ous = jsonl_load(format!(".rusthound-cache/{}/ous.jsonl", options.domain))?;
    results.gpos = jsonl_load(format!(".rusthound-cache/{}/gpos.jsonl", options.domain))?;
    results.containers = jsonl_load(format!(
        ".rusthound-cache/{}/containers.jsonl",
        options.domain
    ))?;

    // Functions to replace and add missing values
    check_all_result(
        options,
        &mut results.users,
        &mut results.groups,
        &mut results.computers,
        &mut results.ous,
        &mut results.domains,
        &mut results.gpos,
        &mut results.fsps,
        &mut results.containers,
        &mut results.trusts,
        &mut results.ntauthstores,
        &mut results.aiacas,
        &mut results.rootcas,
        &mut results.enterprisecas,
        &mut results.certtemplates,
        &mut results.issuancepolicies,
        &results.mappings.dn_sid,
        &results.mappings.sid_type,
        &results.mappings.fqdn_sid,
        &results.mappings.fqdn_ip,
    )?;

    Ok(results)
}

pub fn export_results(
    common_args: &Options,
    results: Results,
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
