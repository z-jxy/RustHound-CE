use serde_json::value::Value;

use std::collections::HashMap;
use colored::Colorize;
use log::{info,debug,trace};

use std::fs;
use std::fs::File;
use std::io::{Seek, Write};
use zip::result::ZipResult;
use zip::write::{SimpleFileOptions,ZipWriter};

extern crate zip;
use crate::args::{Options, RUSTHOUND_VERSION};
use crate::objects::common::{FinalJson,Meta,LdapObject};

/// Current Bloodhound version 4.3+
pub const BLOODHOUND_VERSION_4: i8 = 6;

// Function to create the .json file.
pub fn add_file<T: LdapObject>(
   datetime: &String,
   name: String,
   domain_format: &String,
   vec_json: Vec<T>,
   json_result: &mut HashMap<String, String>,
   common_args: &Options, 
 ) -> std::io::Result<()>
 {
  if !vec_json.is_empty() {
    debug!("Making {}.json",&name);
  
    let path = &common_args.path;
    let zip = common_args.zip;
    let count = vec_json.len();
  
    let mut result: Vec<Value> = Vec::new();
    for object in vec_json {
        result.push(object.to_json().to_owned());
    }
    // Prepare template and get result in const var
    let final_json = FinalJson::new(
        result,
        Meta::new(
          000000_i32,
          name.to_owned(),
          count as i32,
          BLOODHOUND_VERSION_4,
          format!("RustHound-CE v{}",RUSTHOUND_VERSION.to_owned())
        )
    );
  
    info!("{} {} parsed!", count.to_string().bold(),&name);
  
    // result
    fs::create_dir_all(path)?;
  
    // Create json file if isn't zip
    if ! zip 
    {
        let final_path = format!("{path}/{datetime}_{domain_format}_{name}.json");
        fs::write(&final_path, serde_json::to_string(&final_json)?)?;
        info!("{} created!",final_path.bold());
    }
    else
    {
        json_result.insert(format!("{datetime}_{domain_format}_{name}.json").to_string(),serde_json::to_string(&final_json)?);
    }
  }
  Ok(())
 }
 
 /// Function to compress the JSON files into a zip archive
 pub fn make_a_zip(
   datetime: &String,
   domain: &String,
   path: &String,
   json_result: &HashMap<String, String>
 ){
   let final_path = format!("{path}/{datetime}_{domain}_rusthound-ce.zip");
   let mut file = File::create(&final_path).expect("Couldn't create file");
   create_zip_archive(&mut file, json_result).expect("Couldn't create archive");
 
   info!("{} created!",&final_path.bold());
 }
 
 
 fn create_zip_archive<T: Seek + Write>(zip_filename: &mut T,json_result: &HashMap<String, String>) -> ZipResult<()> {
   let mut writer = ZipWriter::new(zip_filename);
   // json file by json file
   trace!("Making the ZIP file");
 
   for file in json_result
   {
      let filename = file.0;
      let content = file.1;
      trace!("Adding file {}",filename.bold());
      let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
      writer.start_file(filename, options)?;
      writer.write_all(content.as_bytes())?;
   }
 
   writer.finish()?;
   Ok(())
 }