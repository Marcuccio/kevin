#![allow(dead_code)]

use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::fmt;
use serde::{Deserialize};

const URL_KEVIN: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const URL_INTHEWILD: &str = "https://inthewild.io/api/exploited";

mod util;

#[derive(Debug)]
pub struct Source {
    is_kev: bool,
    is_inthewild: bool,
    is_nuclei: bool,
}

impl Source {
    fn new() -> Self {
        Self {
            is_kev: false,
            is_inthewild: false,
            is_nuclei: false,
        }
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sources = Vec::new();
        sources.push(self.is_kev.to_string());
        sources.push(self.is_inthewild.to_string());
        sources.push(self.is_nuclei.to_string());
        write!(f, "{}", sources.join(","))
    }
}


#[allow(unused_variables)]
#[derive(Debug, Deserialize)]
struct Inthewild {
    id: String,
    #[serde(rename = "earliestReport")]
    earliest_report: String
}

#[allow(unused_variables)]
#[derive(Debug, Deserialize)]
struct KevWrapper {
    title: String,
    #[serde(rename = "catalogVersion")]
    catalog_version: String,
    #[serde(rename = "dateReleased")]
    date_released: String,
    count: u16,
    vulnerabilities: Vec<Kev>
}

#[allow(unused_variables)]
#[derive(Debug, Deserialize)]
struct Kev {
    #[serde(rename = "cveID")]
    id: String,
    #[serde(rename = "vendorProject")]
    vendor_project: String,
    product: String,
    #[serde(rename = "vulnerabilityName")]
    vulnerability_name: String,
    #[serde(rename = "dateAdded")]
    date_added: String,
    #[serde(rename = "shortDescription")]
    short_description: String,
    #[serde(rename = "requiredAction")]
    required_action: String,
    #[serde(rename = "dueDate")]
    due_date: String,
    notes: String
 }

fn filter_cve(input: &[String], known: &[String]) -> Vec<String> {
    input
        .iter()
        .filter(|x| known.contains(x))
        .cloned()
        .collect::<Vec<String>>()
}

fn cves_from_itw(itw: &[Inthewild]) -> Vec<String> {
    let cves = itw
    .iter()
    .map(|x| x.id.clone())
    .collect::<Vec<String>>();
    
    cves
}

fn cves_from_kev(vuln: &[Kev]) -> Vec<String> {
    let cves = vuln
    .iter()
    .map(|x| x.id.clone())
    .collect::<Vec<String>>();
    
    cves
}

fn add_cve_knownledge(report: &mut HashMap<String, Source>, itw: &[Inthewild], kev: &KevWrapper, nuc_cve: &[String]) {
    let itw_cve = cves_from_itw(itw);
    let kev_cve = cves_from_kev(&kev.vulnerabilities);

    for (key, value) in report.iter_mut() {
        if itw_cve.contains(key) {
            value.is_inthewild = true;
        }
        if kev_cve.contains(key) {
            value.is_kev = true;
        }
        if nuc_cve.contains(key) {
            value.is_nuclei = true;
        }
    }
}

pub fn run(input: &[String]) -> Result<HashMap<String, Source>, String>{

    let mut report: HashMap<String, Source> = input
    .iter()
    .map(|x| (x.to_owned(), Source::new()))
    .collect();

    let itw: Vec<Inthewild> = serde_json::from_reader(
        util::dwnld_from_url(URL_INTHEWILD).unwrap()
    ).unwrap();
    
    let kev: KevWrapper = serde_json::from_reader(
        util::dwnld_from_url(URL_KEVIN).unwrap()
    ).unwrap();

    let nuc = util::read_file_to_vec("C:\\Users\\mstrambelli\\Tools\\kevin\\src\\nuclei_cves").unwrap();

    add_cve_knownledge(&mut report, &itw, &kev, &nuc);

    println!("cveID,kev,itw,nuclei");
    for (key, value) in report.iter() {
        println!("{},{}", key, value);
    }
    
    Ok(report)
}