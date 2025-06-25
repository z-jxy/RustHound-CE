use crate::cache::CacheHandle;
use crate::ldap::EntrySource;
use crate::objects::common::parse_unknown;
use crate::objects::{
    aiaca::AIACA, certtemplate::CertTemplate, computer::Computer, container::Container,
    domain::Domain, enterpriseca::EnterpriseCA, fsp::Fsp, gpo::Gpo, group::Group,
    inssuancepolicie::IssuancePolicie, ntauthstore::NtAuthStore, ou::Ou, rootca::RootCA,
    trust::Trust, user::User,
};
use crate::ADResults;
use indicatif::ProgressBar;
use ldap3::SearchEntry;
use log::info;
use regex::Regex;
use std::convert::TryInto;
use std::error::Error;

use crate::args::Options;
use crate::banner::progress_bar;
use crate::enums::ldaptype::*;
use crate::enums::regex::{PARSER_MOD_RE1, PARSER_MOD_RE2};

// use crate::modules::adcs::parser::{parse_adcs_ca,parse_adcs_template};

/// Function to get type for object by object
pub fn parse_result_type_from_mem(
    common_args: &Options,
    result: Vec<SearchEntry>,
) -> Result<ADResults, Box<dyn Error>> {
    let mut results = ADResults::new();
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

    let dn_sid = &mut results.mappings.dn_sid;
    let sid_type = &mut results.mappings.sid_type;
    let fqdn_sid = &mut results.mappings.fqdn_sid;
    let fqdn_ip = &mut results.mappings.fqdn_ip;

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
                results.users.push(user);
            }
            Type::Group => {
                let mut group = Group::new();
                group.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.groups.push(group);
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
                results.computers.push(computer);
            }
            Type::Ou => {
                let mut ou = Ou::new();
                ou.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.ous.push(ou);
            }
            Type::Domain => {
                let mut domain_object = Domain::new();
                let domain_sid_from_domain =
                    domain_object.parse(entry, domain, dn_sid, sid_type)?;
                domain_sid = domain_sid_from_domain;
                results.domains.push(domain_object);
            }
            Type::Gpo => {
                let mut gpo = Gpo::new();
                gpo.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.gpos.push(gpo);
            }
            Type::ForeignSecurityPrincipal => {
                let mut security_principal = Fsp::new();
                security_principal.parse(entry, domain, dn_sid, sid_type)?;
                results.fsps.push(security_principal);
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
                results.containers.push(container);
            }
            Type::Trust => {
                let mut trust = Trust::new();
                trust.parse(entry, domain)?;
                results.trusts.push(trust);
            }
            Type::NtAutStore => {
                let mut nt_auth_store = NtAuthStore::new();
                nt_auth_store.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.ntauthstores.push(nt_auth_store);
            }
            Type::AIACA => {
                let mut aiaca = AIACA::new();
                aiaca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.aiacas.push(aiaca);
            }
            Type::RootCA => {
                let mut root_ca = RootCA::new();
                root_ca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.rootcas.push(root_ca);
            }
            Type::EnterpriseCA => {
                let mut enterprise_ca = EnterpriseCA::new();
                enterprise_ca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.enterprisecas.push(enterprise_ca);
            }
            Type::CertTemplate => {
                let mut cert_template = CertTemplate::new();
                cert_template.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.certtemplates.push(cert_template);
            }
            Type::IssuancePolicie => {
                let mut issuance_policie = IssuancePolicie::new();
                issuance_policie.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.issuancepolicies.push(issuance_policie);
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

    pb.finish_and_clear();
    info!("Parsing LDAP objects finished!");
    Ok(results)
}

// for `total_objects`, the total number of objects may not be known if the ldap query was never run
// (e.g run was resumed from cached results)
pub fn parse_result_type_from_cache(
    common_args: &Options,
    ldap_cache_path: CacheHandle,
    total_objects: Option<usize>,
) -> Result<ADResults, Box<dyn Error>> {
    let mut results = ADResults::default();
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

    let dn_sid = &mut results.mappings.dn_sid;
    let sid_type = &mut results.mappings.sid_type;
    let fqdn_sid = &mut results.mappings.fqdn_sid;
    let fqdn_ip = &mut results.mappings.fqdn_ip;

    for entry in ldap_cache_path {
        let entry: SearchEntry = entry?.into();
        // Start parsing with Type matching
        let atype = get_type(&entry).unwrap_or(Type::Unknown);
        match atype {
            Type::User => {
                let mut user: User = User::new();
                user.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.users.push(user);
            }
            Type::Group => {
                let mut group = Group::new();
                group.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.groups.push(group);
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
                results.computers.push(computer);
            }
            Type::Ou => {
                let mut ou = Ou::new();
                ou.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.ous.push(ou);
            }
            Type::Domain => {
                let mut domain_object = Domain::new();
                let domain_sid_from_domain =
                    domain_object.parse(entry, domain, dn_sid, sid_type)?;
                domain_sid = domain_sid_from_domain;
                results.domains.push(domain_object);
            }
            Type::Gpo => {
                let mut gpo = Gpo::new();
                gpo.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.gpos.push(gpo);
            }
            Type::ForeignSecurityPrincipal => {
                let mut security_principal = Fsp::new();
                security_principal.parse(entry, domain, dn_sid, sid_type)?;
                results.fsps.push(security_principal);
            }
            Type::Container => {
                if PARSER_MOD_RE1.is_match(&entry.dn.to_uppercase())
                    || PARSER_MOD_RE2.is_match(&entry.dn.to_uppercase())
                {
                    //trace!("Container not to add: {}",&cloneresult.dn.to_uppercase());
                    continue;
                }

                //trace!("Container: {}",&entry.dn.to_uppercase());
                let mut container = Container::new();
                container.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.containers.push(container);
            }
            Type::Trust => {
                let mut trust = Trust::new();
                trust.parse(entry, domain)?;
                results.trusts.push(trust);
            }
            Type::NtAutStore => {
                let mut nt_auth_store = NtAuthStore::new();
                nt_auth_store.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.ntauthstores.push(nt_auth_store);
            }
            Type::AIACA => {
                let mut aiaca = AIACA::new();
                aiaca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.aiacas.push(aiaca);
            }
            Type::RootCA => {
                let mut root_ca = RootCA::new();
                root_ca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.rootcas.push(root_ca);
            }
            Type::EnterpriseCA => {
                let mut enterprise_ca = EnterpriseCA::new();
                enterprise_ca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.enterprisecas.push(enterprise_ca);
            }
            Type::CertTemplate => {
                let mut cert_template = CertTemplate::new();
                cert_template.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.certtemplates.push(cert_template);
            }
            Type::IssuancePolicie => {
                let mut issuance_policie = IssuancePolicie::new();
                issuance_policie.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.issuancepolicies.push(issuance_policie);
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

    pb.finish_and_clear();
    info!("Parsing LDAP objects finished!");
    Ok(results)
}

// for `total_objects`, the total number of objects may not be known if the ldap query was never run
// (e.g run was resumed from cached results)
pub fn parse_result_type_from_source(
    common_args: &Options,
    source: impl EntrySource,
    total_objects: Option<usize>,
) -> Result<ADResults, Box<dyn Error>> {
    let mut results = ADResults::default();
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

    let dn_sid = &mut results.mappings.dn_sid;
    let sid_type = &mut results.mappings.sid_type;
    let fqdn_sid = &mut results.mappings.fqdn_sid;
    let fqdn_ip = &mut results.mappings.fqdn_ip;

    for entry in source.into_entry_iter() {
        let entry: SearchEntry = entry?.into();
        // Start parsing with Type matching
        let atype = get_type(&entry).unwrap_or(Type::Unknown);
        match atype {
            Type::User => {
                let mut user: User = User::new();
                user.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.users.push(user);
            }
            Type::Group => {
                let mut group = Group::new();
                group.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.groups.push(group);
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
                results.computers.push(computer);
            }
            Type::Ou => {
                let mut ou = Ou::new();
                ou.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.ous.push(ou);
            }
            Type::Domain => {
                let mut domain_object = Domain::new();
                let domain_sid_from_domain =
                    domain_object.parse(entry, domain, dn_sid, sid_type)?;
                domain_sid = domain_sid_from_domain;
                results.domains.push(domain_object);
            }
            Type::Gpo => {
                let mut gpo = Gpo::new();
                gpo.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.gpos.push(gpo);
            }
            Type::ForeignSecurityPrincipal => {
                let mut security_principal = Fsp::new();
                security_principal.parse(entry, domain, dn_sid, sid_type)?;
                results.fsps.push(security_principal);
            }
            Type::Container => {
                if PARSER_MOD_RE1.is_match(&entry.dn.to_uppercase())
                    || PARSER_MOD_RE2.is_match(&entry.dn.to_uppercase())
                {
                    //trace!("Container not to add: {}",&cloneresult.dn.to_uppercase());
                    continue;
                }

                //trace!("Container: {}",&entry.dn.to_uppercase());
                let mut container = Container::new();
                container.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.containers.push(container);
            }
            Type::Trust => {
                let mut trust = Trust::new();
                trust.parse(entry, domain)?;
                results.trusts.push(trust);
            }
            Type::NtAutStore => {
                let mut nt_auth_store = NtAuthStore::new();
                nt_auth_store.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.ntauthstores.push(nt_auth_store);
            }
            Type::AIACA => {
                let mut aiaca = AIACA::new();
                aiaca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.aiacas.push(aiaca);
            }
            Type::RootCA => {
                let mut root_ca = RootCA::new();
                root_ca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.rootcas.push(root_ca);
            }
            Type::EnterpriseCA => {
                let mut enterprise_ca = EnterpriseCA::new();
                enterprise_ca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.enterprisecas.push(enterprise_ca);
            }
            Type::CertTemplate => {
                let mut cert_template = CertTemplate::new();
                cert_template.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.certtemplates.push(cert_template);
            }
            Type::IssuancePolicie => {
                let mut issuance_policie = IssuancePolicie::new();
                issuance_policie.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.issuancepolicies.push(issuance_policie);
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

    pb.finish_and_clear();
    info!("Parsing LDAP objects finished!");
    Ok(results)
}
