use chrono::{NaiveDateTime, Local};
use std::convert::TryInto;
use std::error::Error;
//use log::trace;
// special thanks to: https://github.com/NH-RED-TEAM/RustHound/pull/30/commits/e4b5dbc0f147dd0f8efe64d515e0a18b69937aeb

/// Change date timestamp format to epoch format.
pub fn convert_timestamp(timestamp: i64) -> i64
{
    let offset: i64 = 134774*24*60*60;
    let epoch: i64 = timestamp/10000000-offset;
    return epoch
}

pub fn string_to_epoch(date: &str) -> Result<i64, Box<dyn Error>> {
    // Extract the portion before the dot
    // yyyyMMddHHmmss.0z to epoch format
    let str_representation = date.split('.').next().ok_or("Invalid date format")?;
    
    // Parse the date and convert to epoch
    let naive_date = NaiveDateTime::parse_from_str(str_representation, "%Y%m%d%H%M%S")?;
    Ok(naive_date.and_utc().timestamp())
}


/// Function to return current hours.
pub fn return_current_time() -> String
{
    return Local::now().format("%T").to_string()
}

/// Function to return current date.
pub fn return_current_date() -> String
{
    return Local::now().format("%D").to_string()
}

/// Function to return current date.
pub fn return_current_fulldate() -> String
{
    return Local::now().format("%Y%m%d%H%M%S").to_string()
}

/// Function to convert pKIExpirationPeriod Vec<u8> format to u64.
pub fn filetime_to_span(filetime: Vec<u8>) -> Result<u64, Box<dyn Error>> {
    if filetime.len() > 0 {
        let mut span = i64::from_ne_bytes(filetime[0..8].try_into()?) as f64;
        span *= -0.0000001;
        return Ok(span as u64)
    }
    Ok(0)
}

/// Function to change span format to String output date.
/// Thanks to ly4k works: <https://github.com/ly4k/Certipy/blob/main/certipy/commands/find.py#L48>
pub fn span_to_string(span: u64) -> String {
    if (span % 31536000 == 0) && ((span / 31536000) >= 1) {
        if (span / 31536000) == 1 {
            return "1 year".to_string()
        } else {
            return format!("{} years",(span / 31536000))
        }
    } else if (span % 2592000 == 0) && ((span / 2592000) >= 1) {
        if (span / 2592000) == 1 {
            return "1 month".to_string()
        } else {
            return format!("{} months",(span / 2592000))
        }
    } else if (span % 604800 == 0) && ((span / 604800) >= 1) {
        if (span / 604800) == 1 {
            return "1 week".to_string()
        } else {
            return format!("{} weeks",(span / 604800))
        }
    } else if (span % 86400 == 0) && ((span / 86400) >= 1) {
        if (span / 86400) == 1 {
            return "1 day".to_string()
        } else {
            return format!("{} days",(span / 86400))
        }
    } else if (span % 3600 == 0) && ((span / 3600) >= 1) {
        if (span / 3600) == 1 {
            return "1 hour".to_string()
        } else {
            return format!("{} hours",(span / 3600))
        }
    } else {
        return "".to_string()
    }
}