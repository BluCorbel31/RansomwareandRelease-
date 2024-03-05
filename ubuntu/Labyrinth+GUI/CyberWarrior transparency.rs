//Bash#!
cargo run --release -- <directory_path>

//rust
use std::fs;
use std::fs::Metadata;
use std::path::Path;
use std::time::SystemTime;

// Function to get the last modified time of a file or directory
fn get_last_modified_time(path: &Path) -> Option<SystemTime> {
    fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
}

// Function to recursively list all files and directories in a directory
fn list_files_recursive(dir: &Path) -> Vec<fs::DirEntry> {
    let mut files = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(list_files_recursive(&path));
            } else {
                files.push(entry);
            }
        }
    }

    files
}

// Function to organize files and directories by last modified time and make them readable
fn organize_and_make_readable(dir: &Path) -> Result<(), std::io::Error> {
    let mut files = list_files_recursive(dir);

    // Sort files by last modified time
    files.sort_by_key(|entry| get_last_modified_time(&entry.path()));

    for entry in files {
        let path = entry.path();
        let metadata = fs::metadata(&path)?;
        
        // Make the file readable
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o644); // Sets permissions to rw-r--r--
        fs::set_permissions(&path, permissions)?;

        println!("Set permissions for {:?} to readable", path);
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <directory_path>", args[0]);
        std::process::exit(1);
    }

    let dir_path = Path::new(&args[1]);

    match organize_and_make_readable(&dir_path) {
        Ok(()) => println!("Files and directories organized and made readable successfully."),
        Err(e) => eprintln!("Error: {}", e),
    }
}