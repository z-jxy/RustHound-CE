use std::collections::HashMap;
use std::error::Error;

use crate::args::Options;
use crate::enums::{ldaptype::*, templates_enabled_change_displayname_to_sid};
use crate::objects::{
    aiaca::AIACA, certtemplate::CertTemplate, computer::Computer, container::Container,
    domain::Domain, enterpriseca::EnterpriseCA, fsp::Fsp, gpo::Gpo, group::Group,
    inssuancepolicie::IssuancePolicie, ntauthstore::NtAuthStore, ou::Ou, rootca::RootCA,
    trust::Trust, user::User,
};
use log::{debug, info};
pub mod common;

/// Functions to replace and add missing values
#[allow(clippy::too_many_arguments)]
pub fn check_all_result(
    common_args: &Options,
    vec_users: &mut Vec<User>,
    vec_groups: &mut Vec<Group>,
    vec_computers: &mut [Computer],
    vec_ous: &mut [Ou],
    vec_domains: &mut Vec<Domain>,
    vec_gpos: &mut [Gpo],
    _vec_fsps: &mut [Fsp],
    vec_containers: &mut [Container],
    vec_trusts: &mut [Trust],
    vec_ntauthstores: &mut [NtAuthStore],
    vec_aiacas: &mut [AIACA],
    vec_rootcas: &mut [RootCA],
    vec_enterprisecas: &mut [EnterpriseCA],
    vec_certtemplates: &mut [CertTemplate],
    vec_issuancepolicies: &mut [IssuancePolicie],
    dn_sid: &HashMap<String, String>,
    sid_type: &HashMap<String, String>,
    fqdn_sid: &HashMap<String, String>,
    _fqdn_ip: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    let domain = &common_args.domain;
    info!("Starting checker to replace some values...");

    debug!("Replace SID with checker.rs started");
    common::replace_fqdn_by_sid(Type::User, vec_users, fqdn_sid)?;
    common::replace_fqdn_by_sid(Type::Computer, vec_computers, fqdn_sid)?;
    templates_enabled_change_displayname_to_sid(vec_certtemplates, vec_enterprisecas)?;
    common::replace_sid_members(vec_groups, dn_sid, sid_type, vec_trusts)?;
    debug!("Replace SID finished!");

    debug!("Adding defaults groups and default users");
    common::add_default_groups(vec_groups, vec_computers, domain.to_owned())?;
    common::add_default_users(vec_users, domain.to_owned())?;
    debug!("Defaults groups and default users added!");

    debug!("Adding PrincipalType for ACEs started");
    common::add_type_for_ace(vec_users, sid_type)?;
    common::add_type_for_ace(vec_groups, sid_type)?;
    common::add_type_for_ace(vec_computers, sid_type)?;
    common::add_type_for_ace(vec_gpos, sid_type)?;
    common::add_type_for_ace(vec_ous, sid_type)?;
    common::add_type_for_ace(vec_domains, sid_type)?;
    common::add_type_for_ace(vec_containers, sid_type)?;
    common::add_type_for_ace(vec_ntauthstores, sid_type)?;
    common::add_type_for_ace(vec_aiacas, sid_type)?;
    common::add_type_for_ace(vec_rootcas, sid_type)?;
    common::add_type_for_ace(vec_enterprisecas, sid_type)?;
    common::add_type_for_ace(vec_certtemplates, sid_type)?;
    common::add_type_for_ace(vec_issuancepolicies, sid_type)?;

    common::add_type_for_allowtedtoact(vec_computers, sid_type)?;
    debug!("PrincipalType for ACEs added!");

    debug!("Adding ChildObject members started");
    common::add_childobjects_members(vec_ous, dn_sid, sid_type)?;
    common::add_childobjects_members(vec_domains, dn_sid, sid_type)?;
    common::add_childobjects_members(vec_containers, dn_sid, sid_type)?;
    debug!("ChildObject members added!");

    debug!("Adding ContainedBy value started");
    common::add_contained_by_for(vec_users, dn_sid, sid_type)?;

    common::add_contained_by_for(vec_groups, dn_sid, sid_type)?;
    common::add_contained_by_for(vec_computers, dn_sid, sid_type)?;
    common::add_contained_by_for(vec_gpos, dn_sid, sid_type)?;
    common::add_contained_by_for(vec_ous, dn_sid, sid_type)?;
    common::add_contained_by_for(vec_containers, dn_sid, sid_type)?;
    common::add_contained_by_for(vec_ntauthstores, dn_sid, sid_type)?;
    common::add_contained_by_for(vec_aiacas, dn_sid, sid_type)?;
    common::add_contained_by_for(vec_rootcas, dn_sid, sid_type)?;
    common::add_contained_by_for(vec_enterprisecas, dn_sid, sid_type)?;
    common::add_contained_by_for(vec_certtemplates, dn_sid, sid_type)?;
    common::add_contained_by_for(vec_issuancepolicies, dn_sid, sid_type)?;

    debug!("ContainedBy value added!");

    debug!("Adding affected computers in GpoChanges");
    common::add_affected_computers(vec_domains, sid_type)?;
    common::add_affected_computers_for_ou(vec_ous, dn_sid, sid_type)?;
    debug!("Affected computers in GpoChanges added!");

    debug!("Replacing guid for gplinks started");
    common::replace_guid_gplink(vec_ous, dn_sid)?;
    common::replace_guid_gplink(vec_domains, dn_sid)?;
    debug!("guid for gplinks added!");

    if !vec_trusts.is_empty() {
        debug!("Adding trust domain relation");
        common::add_trustdomain(vec_domains, vec_trusts)?;
        debug!("Trust domain relation added!");
    }
    info!("Checking and replacing some values finished!");
    Ok(())
}

pub fn check_ad_result(
    common_args: &Options,
    ad_results: &mut crate::ADResults,
) -> Result<(), Box<dyn Error>> {
    let domain = &common_args.domain;
    info!("Starting checker to replace some values...");

    let &mut crate::ADResults {
        ref mut users,
        ref mut groups,
        ref mut computers,
        ref mut ous,
        ref mut domains,
        ref mut gpos,
        // ref mut fsps, // Not used
        ref mut containers,
        ref mut trusts,
        ref mut ntauthstores,
        ref mut aiacas,
        ref mut rootcas,
        ref mut enterprisecas,
        ref mut certtemplates,
        ref mut issuancepolicies,
        ref mappings,
        ..
    } = ad_results;

    let crate::DomainMappings {
        ref dn_sid,
        ref sid_type,
        ref fqdn_sid,
        // ref fqdn_ip,
        ..
    } = mappings;

    debug!("Replace SID with checker.rs started");
    common::replace_fqdn_by_sid(Type::User, users, fqdn_sid)?;
    common::replace_fqdn_by_sid(Type::Computer, computers, fqdn_sid)?;
    templates_enabled_change_displayname_to_sid(certtemplates, enterprisecas)?;
    common::replace_sid_members(groups, dn_sid, sid_type, trusts)?;
    debug!("Replace SID finished!");

    debug!("Adding defaults groups and default users");
    common::add_default_groups(groups, computers, domain.to_owned())?;
    common::add_default_users(users, domain.to_owned())?;
    debug!("Defaults groups and default users added!");

    debug!("Adding PrincipalType for ACEs started");
    common::add_type_for_ace(users, sid_type)?;
    common::add_type_for_ace(groups, sid_type)?;
    common::add_type_for_ace(computers, sid_type)?;
    common::add_type_for_ace(gpos, sid_type)?;
    common::add_type_for_ace(ous, sid_type)?;
    common::add_type_for_ace(domains, sid_type)?;
    common::add_type_for_ace(containers, sid_type)?;
    common::add_type_for_ace(ntauthstores, sid_type)?;
    common::add_type_for_ace(aiacas, sid_type)?;
    common::add_type_for_ace(rootcas, sid_type)?;
    common::add_type_for_ace(enterprisecas, sid_type)?;
    common::add_type_for_ace(certtemplates, sid_type)?;
    common::add_type_for_ace(issuancepolicies, sid_type)?;

    common::add_type_for_allowtedtoact(computers, sid_type)?;
    debug!("PrincipalType for ACEs added!");

    debug!("Adding ChildObject members started");
    common::add_childobjects_members(ous, dn_sid, sid_type)?;
    common::add_childobjects_members(domains, dn_sid, sid_type)?;
    common::add_childobjects_members(containers, dn_sid, sid_type)?;
    debug!("ChildObject members added!");

    debug!("Adding ContainedBy value started");
    common::add_contained_by_for(users, dn_sid, sid_type)?;

    common::add_contained_by_for(groups, dn_sid, sid_type)?;
    common::add_contained_by_for(computers, dn_sid, sid_type)?;
    common::add_contained_by_for(gpos, dn_sid, sid_type)?;
    common::add_contained_by_for(ous, dn_sid, sid_type)?;
    common::add_contained_by_for(containers, dn_sid, sid_type)?;
    common::add_contained_by_for(ntauthstores, dn_sid, sid_type)?;
    common::add_contained_by_for(aiacas, dn_sid, sid_type)?;
    common::add_contained_by_for(rootcas, dn_sid, sid_type)?;
    common::add_contained_by_for(enterprisecas, dn_sid, sid_type)?;
    common::add_contained_by_for(certtemplates, dn_sid, sid_type)?;
    common::add_contained_by_for(issuancepolicies, dn_sid, sid_type)?;

    debug!("ContainedBy value added!");

    debug!("Adding affected computers in GpoChanges");
    common::add_affected_computers(domains, sid_type)?;
    common::add_affected_computers_for_ou(ous, dn_sid, sid_type)?;
    debug!("Affected computers in GpoChanges added!");

    debug!("Replacing guid for gplinks started");
    common::replace_guid_gplink(ous, dn_sid)?;
    common::replace_guid_gplink(domains, dn_sid)?;
    debug!("guid for gplinks added!");

    if !trusts.is_empty() {
        debug!("Adding trust domain relation");
        common::add_trustdomain(domains, trusts)?;
        debug!("Trust domain relation added!");
    }
    info!("Checking and replacing some values finished!");
    Ok(())
}
