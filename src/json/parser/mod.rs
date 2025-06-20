use crate::io::iter::BincodeIterator;
use crate::io::{DiskBuffer, JsonLObjectBuffer};
use crate::ldap::LdapSearchEntry;
use crate::objects::common::parse_unknown;
use crate::objects::{
    aiaca::AIACA, certtemplate::CertTemplate, computer::Computer, container::Container,
    domain::Domain, enterpriseca::EnterpriseCA, fsp::Fsp, gpo::Gpo, group::Group,
    inssuancepolicie::IssuancePolicie, ntauthstore::NtAuthStore, ou::Ou, rootca::RootCA,
    trust::Trust, user::User,
};
use indicatif::ProgressBar;
use ldap3::SearchEntry;
use regex::Regex;
use std::collections::HashMap;
use std::convert::TryInto;
use std::error::Error;

use crate::args::Options;
use crate::banner::progress_bar;
use crate::enums::ldaptype::*;
use log::info;
// use crate::modules::adcs::parser::{parse_adcs_ca,parse_adcs_template};

/// Function to get type for object by object
#[allow(clippy::too_many_arguments)]
pub fn parse_result_type_from_mem(
    common_args: &Options,
    result: Vec<SearchEntry>,
    // vec_users: &mut Vec<User>,
    // vec_groups: &mut Vec<Group>,
    // vec_computers: &mut Vec<Computer>,
    // vec_ous: &mut Vec<Ou>,
    vec_domains: &mut Vec<Domain>,
    // vec_gpos: &mut Vec<Gpo>,
    vec_fsps: &mut Vec<Fsp>,
    // vec_containers: &mut Vec<Container>,
    vec_trusts: &mut Vec<Trust>,
    vec_ntauthstore: &mut Vec<NtAuthStore>,
    vec_aiacas: &mut Vec<AIACA>,
    vec_rootcas: &mut Vec<RootCA>,
    vec_enterprisecas: &mut Vec<EnterpriseCA>,
    vec_certtemplates: &mut Vec<CertTemplate>,
    vec_issuancepolicies: &mut Vec<IssuancePolicie>,

    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
    fqdn_sid: &mut HashMap<String, String>,
    fqdn_ip: &mut HashMap<String, String>,
    // adcs_templates: &mut HashMap<String, Vec<String>>,
) -> Result<(), Box<dyn Error>> {
    // Domain name
    let domain = &common_args.domain;

    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = result.len();
    let mut domain_sid: String = "DOMAIN_SID".to_owned();

    info!("Starting the LDAP objects parsing...");

    let output_dir = format!(".rusthound-cache/{domain}");
    std::fs::create_dir_all(&output_dir)?;

    let mut user_buffer = JsonLObjectBuffer::<User>::new(&format!("{output_dir}/users.jsonl"))?;
    let mut group_buffer = JsonLObjectBuffer::<Group>::new(&format!("{output_dir}/groups.jsonl"))?;
    let mut computer_buffer =
        JsonLObjectBuffer::<Computer>::new(&format!("{output_dir}/computers.jsonl"))?;
    let mut ou_buffer = JsonLObjectBuffer::<Ou>::new(&format!("{output_dir}/ous.jsonl"))?;
    let mut gpo_buffer = JsonLObjectBuffer::<Gpo>::new(&format!("{output_dir}/gpos.jsonl"))?;
    let mut container_buffer =
        JsonLObjectBuffer::<Container>::new(&format!("{output_dir}/containers.jsonl"))?;

    let (container_re_filt1, container_re_filt2) = (
        Regex::new(r"[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}")?,
        Regex::new(r"CN=DOMAINUPDATES,CN=SYSTEM,")?,
    );

    for entry in result.into_iter() {
        // Start parsing with Type matching
        let atype = get_type(&entry).unwrap_or(Type::Unknown);
        match atype {
            Type::User => {
                let mut user: User = User::new();
                user.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                // vec_users.push(user);
                user_buffer.add(user)?;
            }
            Type::Group => {
                let mut group = Group::new();
                group.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                // vec_groups.push(group);
                group_buffer.add(group)?;
            }
            Type::Computer => {
                let mut computer = Computer::new();
                computer.parse(
                    entry,
                    domain,
                    dn_sid,
                    sid_type,
                    fqdn_sid,
                    fqdn_ip,
                    &domain_sid,
                )?;
                // vec_computers.push(computer);
                computer_buffer.add(computer)?;
            }
            Type::Ou => {
                let mut ou = Ou::new();
                ou.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                // vec_ous.push(ou);
                ou_buffer.add(ou)?;
            }
            Type::Domain => {
                let mut domain_object = Domain::new();
                let domain_sid_from_domain =
                    domain_object.parse(entry, domain, dn_sid, sid_type)?;
                domain_sid = domain_sid_from_domain;
                vec_domains.push(domain_object);
            }
            Type::Gpo => {
                let mut gpo = Gpo::new();
                gpo.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                // vec_gpos.push(gpo);
                gpo_buffer.add(gpo)?;
            }
            Type::ForeignSecurityPrincipal => {
                let mut security_principal = Fsp::new();
                security_principal.parse(entry, domain, dn_sid, sid_type)?;
                vec_fsps.push(security_principal);
            }
            Type::Container => {
                let upper = entry.dn.to_uppercase();
                if container_re_filt1.is_match(&upper) || container_re_filt2.is_match(&upper) {
                    //trace!("Container not to add: {}",&entry.dn.to_uppercase());
                    continue;
                }

                //trace!("Container: {}",&entry.dn.to_uppercase());
                let mut container = Container::new();
                container.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                // vec_containers.push(container);
                container_buffer.add(container)?;
            }
            Type::Trust => {
                let mut trust = Trust::new();
                trust.parse(entry, domain)?;
                vec_trusts.push(trust);
            }
            Type::NtAutStore => {
                let mut nt_auth_store = NtAuthStore::new();
                nt_auth_store.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                vec_ntauthstore.push(nt_auth_store);
            }
            Type::AIACA => {
                let mut aiaca = AIACA::new();
                aiaca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                vec_aiacas.push(aiaca);
            }
            Type::RootCA => {
                let mut root_ca = RootCA::new();
                root_ca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                vec_rootcas.push(root_ca);
            }
            Type::EnterpriseCA => {
                let mut enterprise_ca = EnterpriseCA::new();
                enterprise_ca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                vec_enterprisecas.push(enterprise_ca);
            }
            Type::CertTemplate => {
                let mut cert_template = CertTemplate::new();
                cert_template.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                vec_certtemplates.push(cert_template);
            }
            Type::IssuancePolicie => {
                let mut issuance_policie = IssuancePolicie::new();
                issuance_policie.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                vec_issuancepolicies.push(issuance_policie);
            }
            Type::Unknown => {
                let _unknown = parse_unknown(entry, domain);
            }
        }
        // Manage progress bar
        // Pourcentage (%) = 100 x Valeur partielle/Valeur totale
        count += 1;
        let pourcentage = 100 * count / total;
        progress_bar(
            pb.to_owned(),
            "Parsing LDAP objects".to_string(),
            pourcentage.try_into()?,
            "%".to_string(),
        );
    }

    user_buffer.finish()?;
    group_buffer.finish()?;
    computer_buffer.finish()?;
    ou_buffer.finish()?;
    gpo_buffer.finish()?;
    container_buffer.finish()?;

    pb.finish_and_clear();
    info!("Parsing LDAP objects finished!");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn parse_result_type_from_cache(
    common_args: &Options,
    ldap_cache_path: impl AsRef<std::path::Path>,
    // result: Vec<SearchEntry>,
    // vec_users: &mut Vec<User>,
    // vec_groups: &mut Vec<Group>,
    // vec_computers: &mut Vec<Computer>,
    // vec_ous: &mut Vec<Ou>,
    vec_domains: &mut Vec<Domain>,
    // vec_gpos: &mut Vec<Gpo>,
    vec_fsps: &mut Vec<Fsp>,
    // vec_containers: &mut Vec<Container>,
    vec_trusts: &mut Vec<Trust>,
    vec_ntauthstore: &mut Vec<NtAuthStore>,
    vec_aiacas: &mut Vec<AIACA>,
    vec_rootcas: &mut Vec<RootCA>,
    vec_enterprisecas: &mut Vec<EnterpriseCA>,
    vec_certtemplates: &mut Vec<CertTemplate>,
    vec_issuancepolicies: &mut Vec<IssuancePolicie>,

    dn_sid: &mut HashMap<String, String>,
    sid_type: &mut HashMap<String, String>,
    fqdn_sid: &mut HashMap<String, String>,
    fqdn_ip: &mut HashMap<String, String>,

    total_objects: Option<usize>,
    // adcs_templates: &mut HashMap<String, Vec<String>>,
) -> Result<(), Box<dyn Error>> {
    // Domain name
    let domain = &common_args.domain;

    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = total_objects;
    let mut domain_sid: String = "DOMAIN_SID".to_owned();

    info!("Starting the LDAP objects parsing...");

    let output_dir = format!(".rusthound-cache/{domain}");
    std::fs::create_dir_all(&output_dir)?;

    let mut user_buffer = JsonLObjectBuffer::<User>::new(&format!("{output_dir}/users.jsonl"))?;
    let mut group_buffer = JsonLObjectBuffer::<Group>::new(&format!("{output_dir}/groups.jsonl"))?;
    let mut computer_buffer =
        JsonLObjectBuffer::<Computer>::new(&format!("{output_dir}/computers.jsonl"))?;
    let mut ou_buffer = JsonLObjectBuffer::<Ou>::new(&format!("{output_dir}/ous.jsonl"))?;
    let mut gpo_buffer = JsonLObjectBuffer::<Gpo>::new(&format!("{output_dir}/gpos.jsonl"))?;
    let mut container_buffer =
        JsonLObjectBuffer::<Container>::new(&format!("{output_dir}/containers.jsonl"))?;

    let (container_re_filt1, container_re_filt2) = (
        Regex::new(r"[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}")?,
        Regex::new(r"CN=DOMAINUPDATES,CN=SYSTEM,")?,
    );

    for entry in BincodeIterator::<LdapSearchEntry, _>::from_file(&ldap_cache_path)? {
        let entry: SearchEntry = entry?.into();
        // Start parsing with Type matching
        let atype = get_type(&entry).unwrap_or(Type::Unknown);
        match atype {
            Type::User => {
                let mut user: User = User::new();
                user.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                // vec_users.push(user);
                user_buffer.add(user)?;
            }
            Type::Group => {
                let mut group = Group::new();
                group.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                // vec_groups.push(group);
                group_buffer.add(group)?;
            }
            Type::Computer => {
                let mut computer = Computer::new();
                computer.parse(
                    entry,
                    domain,
                    dn_sid,
                    sid_type,
                    fqdn_sid,
                    fqdn_ip,
                    &domain_sid,
                )?;
                // vec_computers.push(computer);
                computer_buffer.add(computer)?;
            }
            Type::Ou => {
                let mut ou = Ou::new();
                ou.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                // vec_ous.push(ou);
                ou_buffer.add(ou)?;
            }
            Type::Domain => {
                let mut domain_object = Domain::new();
                let domain_sid_from_domain =
                    domain_object.parse(entry, domain, dn_sid, sid_type)?;
                domain_sid = domain_sid_from_domain;
                vec_domains.push(domain_object);
            }
            Type::Gpo => {
                let mut gpo = Gpo::new();
                gpo.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                // vec_gpos.push(gpo);
                gpo_buffer.add(gpo)?;
            }
            Type::ForeignSecurityPrincipal => {
                let mut security_principal = Fsp::new();
                security_principal.parse(entry, domain, dn_sid, sid_type)?;
                vec_fsps.push(security_principal);
            }
            Type::Container => {
                let upper = entry.dn.to_uppercase();
                if container_re_filt1.is_match(&upper) || container_re_filt2.is_match(&upper) {
                    //trace!("Container not to add: {}",&entry.dn.to_uppercase());
                    continue;
                }

                //trace!("Container: {}",&entry.dn.to_uppercase());
                let mut container = Container::new();
                container.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                // vec_containers.push(container);
                container_buffer.add(container)?;
            }
            Type::Trust => {
                let mut trust = Trust::new();
                trust.parse(entry, domain)?;
                vec_trusts.push(trust);
            }
            Type::NtAutStore => {
                let mut nt_auth_store = NtAuthStore::new();
                nt_auth_store.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                vec_ntauthstore.push(nt_auth_store);
            }
            Type::AIACA => {
                let mut aiaca = AIACA::new();
                aiaca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                vec_aiacas.push(aiaca);
            }
            Type::RootCA => {
                let mut root_ca = RootCA::new();
                root_ca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                vec_rootcas.push(root_ca);
            }
            Type::EnterpriseCA => {
                let mut enterprise_ca = EnterpriseCA::new();
                enterprise_ca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                vec_enterprisecas.push(enterprise_ca);
            }
            Type::CertTemplate => {
                let mut cert_template = CertTemplate::new();
                cert_template.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                vec_certtemplates.push(cert_template);
            }
            Type::IssuancePolicie => {
                let mut issuance_policie = IssuancePolicie::new();
                issuance_policie.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                vec_issuancepolicies.push(issuance_policie);
            }
            Type::Unknown => {
                let _unknown = parse_unknown(entry, domain);
            }
        }
        // Manage progress bar
        // Pourcentage (%) = 100 x Valeur partielle/Valeur totale
        if let Some(total) = total {
            count += 1;
            let pourcentage = 100 * count / total;
            progress_bar(
                pb.to_owned(),
                "Parsing LDAP objects".to_string(),
                pourcentage.try_into()?,
                "%".to_string(),
            );
        }
    }

    user_buffer.finish()?;
    group_buffer.finish()?;
    computer_buffer.finish()?;
    ou_buffer.finish()?;
    gpo_buffer.finish()?;
    container_buffer.finish()?;

    pb.finish_and_clear();
    info!("Parsing LDAP objects finished!");
    Ok(())
}
