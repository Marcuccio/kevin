#![allow(dead_code)]
#![allow(unused_variables)]


use std::path::Path;
use std::io::{self,BufRead, BufReader};
use std::fs::File;
use colored::Colorize;
use atty::Stream;

pub fn read_file_to_vec(filename: &str) -> std::io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        lines.push(line?);
    }
    Ok(lines)
}

pub fn dwnld_from_url(url: &str) -> Result<reqwest::blocking::Response, Box<dyn std::error::Error>> {
    let resp = reqwest::blocking::get(url)?;
    Ok(resp)
}

pub fn read_file(path: &str) -> Result<File, std::io::Error> {
    let file_path = Path::new(path);
    File::open(file_path)
}       

pub fn get_stdio_lines() -> Vec<String> {
    let stdin = io::stdin();
    let lines = stdin.lock().lines();
    let mut lines_vec = Vec::new();
    lines.into_iter().for_each(|line| match line {
        Ok(line) => {
            if line.starts_with("CVE") {
                lines_vec.push(line);
            }
        }
        Err(_) => {
            error("Error reading line from stdin".to_string());
            dbg!();
            std::process::exit(1);
        }
    });
    lines_vec
}

pub fn write_vec_as_stdout(input: &[String]) {
    input.iter().for_each(|x| println!("{x}"));
}


pub fn check_for_stdin() {
    if atty::is(Stream::Stdin) {
        //print_help();
        std::process::exit(0);
    }
}

pub fn debug(msg: String) {
    println!("{} {}", "[DBG]".blue(), msg);
}

pub fn info(msg: String) {
    println!("{} {}", "[INF]".blue(), msg);
}

pub fn warn(msg: String) {
    println!("{} {}", "[WRN]".yellow(), msg);
}

pub fn error(msg: String) {
    println!("{} {}", "[ERR]".magenta (), msg);
}