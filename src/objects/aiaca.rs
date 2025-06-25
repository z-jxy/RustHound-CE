use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::prelude::*;
use ldap3::SearchEntry;
use log::{debug, error, trace};
use std::collections::HashMap;
use std::error::Error;

use crate::objects::common::{LdapObject, AceTemplate, SPNTarget, Link, Member};
use crate::enums::{decode_guid_le, parse_ntsecuritydescriptor};
use crate::utils::date::string_to_epoch;
use crate::utils::crypto::calculate_sha1;

/// AIACA structure
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AIACA {
    #[serde(rename = "Properties")]
    properties: AIACAProperties,
    #[serde(rename = "DomainSID")]
    domain_sid: String,
    #[serde(rename = "Aces")]
    aces: Vec<AceTemplate>,
    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(rename = "IsDeleted")]
    is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    is_acl_protected: bool,
    #[serde(rename = "ContainedBy")]
    contained_by: Option<Member>,
}

impl AIACA {
    // New AIACA
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// Function to parse and replace value in json template for AIACA object.
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
        debug!("Parse AIACA: {result_dn}");

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
        self.domain_sid = domain_sid.to_string();

        // With a check
        for (key, value) in &result_attrs {
            match key.as_str() {
                "name" => {
                    let name = format!("{}@{}", &value[0], domain);
                    self.properties.name = name.to_uppercase();
                }
                "description" => {
                    self.properties.description = Some(value[0].to_owned());
                }
                "whenCreated" => {
                    let epoch = string_to_epoch(&value[0])?;
                    if epoch.is_positive() {
                        self.properties.whencreated = epoch;
                    }
                }
                "IsDeleted" => {
                    self.is_deleted = true;
                }
                "crossCertificatePair" => {
                    self.properties.hascrosscertificatepair = true;
                    // self.properties.crosscertificatepair = value[0].to_owned();
                }
                _ => {}
            }
        }

        // For all, bins attributs
        for (key, value) in &result_bin {
            match key.as_str() {
                "objectGUID" => {
                    // objectGUID raw to string
                    let guid = decode_guid_le(&value[0]);
                    self.object_identifier = guid.to_owned();
                }
                "nTSecurityDescriptor" => {
                    // nTSecurityDescriptor raw to string
                    let relations_ace = parse_ntsecuritydescriptor(
                        self,
                        &value[0],
                        "AIACA",
                        &result_attrs,
                        &result_bin,
                        domain,
                    );
                    self.aces = relations_ace;
                }
                "cACertificate" => {
                    //info!("{:?}:{:?}", key,value[0].to_owned());
                    let certsha1: String = calculate_sha1(&value[0]);
                    self.properties.certthumbprint = certsha1.to_owned();
                    self.properties.certname = certsha1.to_owned();
                    self.properties.certchain = vec![certsha1.to_owned()];

                    // Parsing certificate.
                    let res = X509Certificate::from_der(&value[0]);
                    match res {
                        Ok((_rem, cert)) => {
                            // println!("Basic Constraints Extensions:");
                            for ext in cert.extensions() {
                                // println!("{:?} : {:?}",&ext.oid, ext);
                                if ext.oid == oid!(2.5.29 .19) {
                                    // <https://docs.rs/x509-parser/latest/x509_parser/extensions/struct.BasicConstraints.html>
                                    if let ParsedExtension::BasicConstraints(basic_constraints) =
                                        &ext.parsed_extension()
                                    {
                                        let _ca = &basic_constraints.ca;
                                        let _path_len_constraint =
                                            &basic_constraints.path_len_constraint;
                                        // println!("ca: {:?}", _ca);
                                        // println!("path_len_constraint: {:?}", _path_len_constraint);
                                        match _path_len_constraint {
                                            Some(_path_len_constraint) => {
                                                if _path_len_constraint > &0 {
                                                    self.properties.hasbasicconstraints = true;
                                                    self.properties.basicconstraintpathlength =
                                                        _path_len_constraint.to_owned();
                                                } else {
                                                    self.properties.hasbasicconstraints = false;
                                                    self.properties.basicconstraintpathlength = 0;
                                                }
                                            }
                                            None => {
                                                self.properties.hasbasicconstraints = false;
                                                self.properties.basicconstraintpathlength = 0;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => error!("CA x509 certificate parsing failed: {:?}", res),
                    }
                }
                _ => {}
            }
        }

        // Push DN and SID in HashMap
        if self.object_identifier != "SID" {
            dn_sid.insert(
                self.properties.distinguishedname.to_owned(),
                self.object_identifier.to_owned(),
            );
            // Push DN and Type
            sid_type.insert(self.object_identifier.to_owned(), "AIACA".to_string());
        }

        // Trace and return AIACA struct
        // trace!("JSON OUTPUT: {:?}",serde_json::to_string(&self).unwrap());
        Ok(())
    }
}

impl LdapObject for AIACA {
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
        panic!("Not used by current object.");
    }
    fn get_contained_by(&self) -> &Option<Member> {
        &self.contained_by
    }
    fn get_child_objects(&self) -> &Vec<Member> {
        panic!("Not used by current object.");
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
    fn set_links(&mut self, _links: Vec<Link>) {
        // Not used by current object.
    }
    fn set_contained_by(&mut self, contained_by: Option<Member>) {
        self.contained_by = contained_by;
    }
    fn set_child_objects(&mut self, _child_objects: Vec<Member>) {
        // Not used by current object.
    }
}

// AIACA properties structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AIACAProperties {
    domain: String,
    name: String,
    distinguishedname: String,
    domainsid: String,
    isaclprotected: bool,
    description: Option<String>,
    whencreated: i64,
    crosscertificatepair: Vec<String>,
    hascrosscertificatepair: bool,
    certthumbprint: String,
    certname: String,
    certchain: Vec<String>,
    hasbasicconstraints: bool,
    basicconstraintpathlength: u32,
}

impl Default for AIACAProperties {
    fn default() -> AIACAProperties {
        AIACAProperties {
            domain: String::from(""),
            name: String::from(""),
            distinguishedname: String::from(""),
            domainsid: String::from(""),
            isaclprotected: false,
            description: None,
            whencreated: -1,
            crosscertificatepair: Vec::new(),
            hascrosscertificatepair: false,
            certthumbprint: String::from(""),
            certname: String::from(""),
            certchain: Vec::new(),
            hasbasicconstraints: false,
            basicconstraintpathlength: 0,
        }
    }
}
