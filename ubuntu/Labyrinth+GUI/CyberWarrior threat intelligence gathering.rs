// Import necessary libraries
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use reqwest;

// Function to fetch data from a URL and save it to a file
fn fetch_data_and_save(url: &str, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    let response = reqwest::blocking::get(url)?;
    let mut file = File::create(filename)?;

    // Write response body to file
    file.write_all(&response.bytes()?)?;
    Ok(())
}

// Function to download threat intelligence data from various sources
fn download_threat_intelligence() -> Result<(), Box<dyn std::error::Error>> {
    // URLs for threat intelligence sources
    let exploit_db_url = "https://www.exploit-db.com/archive.tar.bz2";
    let crackstation_url = "https://crackstation.net/files/crackstation.txt.gz";
    let kali_linux_forums_url = "https://example.com/kali_linux_forums_data.txt";
    let madhouse_url = "https://example.com/madhouse_data.txt";

    // File paths to save the downloaded data
    let exploit_db_file = "exploit_db_data.tar.bz2";
    let crackstation_file = "crackstation_data.txt.gz";
    let kali_linux_forums_file = "kali_linux_forums_data.txt";
    let madhouse_file = "madhouse_data.txt";

    // Fetch and save data from each source
    fetch_data_and_save(exploit_db_url, exploit_db_file)?;
    fetch_data_and_save(crackstation_url, crackstation_file)?;
    fetch_data_and_save(kali_linux_forums_url, kali_linux_forums_file)?;
    fetch_data_and_save(madhouse_url, madhouse_file)?;

    println!("Threat intelligence data downloaded successfully.");
    Ok(())
}

fn main() {
    // Create a directory to store threat intelligence data if it doesn't exist
    let threat_intel_directory = "threat_intelligence";
    if !Path::new(threat_intel_directory).exists() {
        std::fs::create_dir(threat_intel_directory).expect("Failed to create directory");
    }

    // Change directory to the threat intelligence directory
    std::env::set_current_dir(threat_intel_directory).expect("Failed to change directory");

    // Download threat intelligence data from various sources
    if let Err(err) = download_threat_intelligence() {
        eprintln!("Error downloading threat intelligence data: {}", err);
    }
}