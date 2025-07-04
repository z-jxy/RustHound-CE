use serde_json::value::Value;
use serde::{Deserialize, Serialize};
use ldap3::SearchEntry;
use log::{debug, trace};
use std::collections::HashMap;
use std::error::Error;

use crate::objects::common::{LdapObject, AceTemplate, GPOChange, Link, SPNTarget, Member};
use crate::enums::acl::parse_ntsecuritydescriptor;
use crate::enums::gplink::parse_gplink;
use crate::enums::sid::decode_guid_le;
use crate::utils::date::string_to_epoch;

/// Ou structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Ou {
    #[serde(rename = "GPOChanges")]
    gpo_changes: GPOChange,
    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(rename = "Properties")]
    properties: OuProperties,
    #[serde(rename = "Aces")]
    aces: Vec<AceTemplate>,
    #[serde(rename = "Links")]
    links: Vec<Link>,
    #[serde(rename = "ChildObjects")]
    child_objects: Vec<Member>,
    #[serde(rename = "IsDeleted")]
    is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    is_acl_protected: bool,
    #[serde(rename = "ContainedBy")]
    contained_by: Option<Member>,
}

impl Ou {
    // New computer.
    pub fn new() -> Self { 
        Self { ..Default::default() } 
    }

    // Immutable access.
    pub fn properties(&self) -> &OuProperties {
        &self.properties
    }

    // Mutable access.
    pub fn gpo_changes_mut(&mut self) -> &mut GPOChange {
        &mut self.gpo_changes
    }
    pub fn child_objects_mut(&mut self) -> &mut Vec<Member> {
        &mut self.child_objects
    }

    /// Function to parse and replace value for OU object.
    /// <https://bloodhound.readthedocs.io/en/latest/further-reading/json.html#ous>
    pub fn parse(
        &mut self,
        result: SearchEntry,
        domain: &str,
        dn_sid: &mut HashMap<String, String>,
        sid_type: &mut HashMap<String, String>,
        domain_sid: &str
    ) -> Result<(), Box<dyn Error>> {
        let result_dn: String = result.dn.to_uppercase();
        let result_attrs: HashMap<String, Vec<String>> = result.attrs;
        let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;

        // Debug for current object
        debug!("Parse OU: {result_dn}");

        // Trace all result attributes
        for (key, value) in &result_attrs {
            trace!("  {key:?}:{value:?}");
        }
        // Trace all bin result attributes
        for (key, value) in &result_bin {
            trace!("  {key:?}:{value:?}");
        }

        // Change all values...
        self.properties.domain = domain.to_uppercase();
        self.properties.distinguishedname = result_dn;
        self.properties.domainsid = domain_sid.to_string();

        // Check and replace value
        for (key, value) in &result_attrs {
             match key.as_str() {
                 "name" => {
                     let name = &value[0];
                     let email = format!("{}@{}", name.to_owned(), domain);
                     self.properties.name = email.to_uppercase();
                 }
                 "description" => {
                     self.properties.description = value.first().cloned();
                 }
                 "whenCreated" => {
                     let epoch = string_to_epoch(&value[0])?;
                     if epoch.is_positive() {
                          self.properties.whencreated = epoch;
                     }
                 }
                 "gPLink" => {
                     self.links = parse_gplink(value[0].to_string())?;
                 }
                 "gPOtions" => {
                     self.properties.blocksinheritance = value[0].parse::<i64>().unwrap_or(0) == 1;
                 }
                 "IsDeleted" => {
                     self.is_deleted = true;
                 }
                 _ => {}
             }
        }

          // For all, bins attributes
        for (key, value) in &result_bin {
             match key.as_str() {
                 "objectGUID" => {
                     // objectGUID raw to string
                     self.object_identifier = decode_guid_le(&value[0]).to_owned();
                 }
                 "nTSecurityDescriptor" => {
                     // trace!("nTSecurityDescriptor ACES ACLS ?");
                     // nTSecurityDescriptor raw to string
                     let relations_ace = parse_ntsecuritydescriptor(
                          self,
                          &value[0],
                          "OU",
                          &result_attrs,
                          &result_bin,
                          domain,
                     );
                     self.aces = relations_ace;
                 }
                 _ => {}
             }
        }
        // Push DN and SID in HashMap
        dn_sid.insert(
             self.properties.distinguishedname.to_string(),
             self.object_identifier.to_string(),
        );
        // Push DN and Type
        sid_type.insert(
            self.object_identifier.to_string(),
             "OU".to_string(),
        );

        // Trace and return Ou struct
        // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
        Ok(())
    }
}

impl LdapObject for Ou {
    // To JSON
    fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap()
    }
    
    // Get values
    fn get_object_identifier(&self) -> &String {
        &self.object_identifier
    }
    fn get_is_acl_protected(&self) -> &bool {
        &self.is_acl_protected
    }
    fn get_aces(&self) -> &Vec<AceTemplate> {
        &self.aces
    }
    fn get_spntargets(&self) -> &Vec<SPNTarget> {
        panic!("Not used by current object.");
    }
    fn get_allowed_to_delegate(&self) -> &Vec<Member> {
        panic!("Not used by current object.");
    }
    fn get_links(&self) -> &Vec<Link> {
        &self.links
    }
    fn get_contained_by(&self) -> &Option<Member> {
        &self.contained_by
    }
    fn get_child_objects(&self) -> &Vec<Member> {
        &self.child_objects
    }
    fn get_haslaps(&self) -> &bool {
        &false
    }
    
    // Get mutable values
    fn get_aces_mut(&mut self) -> &mut Vec<AceTemplate> {
        &mut self.aces
    }
    fn get_spntargets_mut(&mut self) -> &mut Vec<SPNTarget> {
        panic!("Not used by current object.");
    }
    fn get_allowed_to_delegate_mut(&mut self) -> &mut Vec<Member> {
        panic!("Not used by current object.");
    }
    
    // Edit values
    fn set_is_acl_protected(&mut self, is_acl_protected: bool) {
        self.is_acl_protected = is_acl_protected;
        self.properties.isaclprotected = is_acl_protected;
    }
    fn set_aces(&mut self, aces: Vec<AceTemplate>) {
        self.aces = aces;
    }
    fn set_spntargets(&mut self, _spn_targets: Vec<SPNTarget>) {
        // Not used by current object.
    }
    fn set_allowed_to_delegate(&mut self, _allowed_to_delegate: Vec<Member>) {
        // Not used by current object.
    }
    fn set_links(&mut self, links: Vec<Link>) {
        self.links = links;
    }
    fn set_contained_by(&mut self, contained_by: Option<Member>) {
        self.contained_by = contained_by;
    }
    fn set_child_objects(&mut self, child_objects: Vec<Member>) {
        self.child_objects = child_objects
    }
}

// Ou properties structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct OuProperties {
    domain: String,
    name: String,
    distinguishedname: String,
    domainsid: String,
    isaclprotected: bool,
    highvalue: bool,
    description: Option<String>,
    whencreated: i64,
    blocksinheritance: bool
}

impl OuProperties {
    // Immutable access.
    pub fn name(&self) -> &String {
        &self.name
    }
    pub fn distinguishedname(&self) -> &String {
        &self.distinguishedname
    }


    pub fn isaclprotected_mut(&mut self) -> &mut bool {
        &mut self.isaclprotected
    }
}