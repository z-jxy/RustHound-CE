use std::collections::HashMap;

use ldap3::SearchEntry;

use crate::{
    args::Options,
    json::{checker::check_all_result, parser::parse_result_type},
    objects::{
        aiaca::AIACA, certtemplate::CertTemplate, computer::Computer, container::Container,
        domain::Domain, enterpriseca::EnterpriseCA, fsp::Fsp, gpo::Gpo, group::Group,
        inssuancepolicie::IssuancePolicie, ntauthstore::NtAuthStore, ou::Ou, rootca::RootCA,
        trust::Trust, user::User,
    },
};

#[derive(Default)]
pub struct Results {
    users: Vec<User>,
    groups: Vec<Group>,
    computers: Vec<Computer>,
    ous: Vec<Ou>,
    domains: Vec<Domain>,
    gpos: Vec<Gpo>,
    fsps: Vec<Fsp>,
    containers: Vec<Container>,
    trusts: Vec<Trust>,
    ntauthstores: Vec<NtAuthStore>,
    aiacas: Vec<AIACA>,
    rootcas: Vec<RootCA>,
    enterprisecas: Vec<EnterpriseCA>,
    certtemplates: Vec<CertTemplate>,
    issuancepolicies: Vec<IssuancePolicie>,

    /// DN to SID
    dn_sid: HashMap<String, String>,
    ///  DN to Type
    sid_type: HashMap<String, String>,
    /// FQDN to SID
    fqdn_sid: HashMap<String, String>,
    /// fqdn to an ip address
    fqdn_ip: HashMap<String, String>,
}

pub async fn prepare_results(
    result: Vec<SearchEntry>,
    options: &Options,
) -> Result<Results, Box<dyn std::error::Error>> {
    let mut results = Results::default();

    // Analyze object by object
    // Get type and parse it to get values
    parse_result_type(
        options,
        result,
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
        &mut results.dn_sid,
        &mut results.sid_type,
        &mut results.fqdn_sid,
        &mut results.fqdn_ip,
    )?;

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
        &mut results.dn_sid,
        &mut results.sid_type,
        &mut results.fqdn_sid,
        &mut results.fqdn_ip,
    )?;

    Ok(results)
}
