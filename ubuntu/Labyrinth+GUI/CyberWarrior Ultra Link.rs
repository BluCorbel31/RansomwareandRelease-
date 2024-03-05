use std::process::{Command, Stdio};
use std::io::{BufReader, BufRead};
use std::thread;

fn read_output_from_script(script_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Create a command to execute the script or executable
    let output = Command::new(script_path)
        .stdout(Stdio::piped())
        .spawn()?;
    
    // Read output from the script or executable
    let stdout = output.stdout.ok_or("Failed to open stdout")?;
    let reader = BufReader::new(stdout);
    for line in reader.lines() {
        match line {
            Ok(line) => {
                // Process each line of output from the script or executable
                println!("Output from {}: {}", script_path, line);
            },
            Err(err) => {
                eprintln!("Error reading output from {}: {}", script_path, err);
            }
        }
    }
    Ok(())
}

fn prioritize_scripts(script_paths: &mut Vec<&str>) {
    // Implement your decision-making logic here
    // For example, you can prioritize based on dependencies, resource requirements, expected execution time, etc.
    // For demonstration, let's prioritize shorter scripts first
    script_paths.sort_by_key(|&path| {
        Command::new(path)
            .output()
            .map(|output| output.stdout.len())
            .unwrap_or(std::usize::MAX)
    });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // List of paths to scripts or executables
    let mut script_paths = vec![
        "/path/to/script1",
        "/path/to/script2",
        "/path/to/script3",
        // Add more script paths as needed
    ];

    // Prioritize the scripts based on decision-making logic
    prioritize_scripts(&mut script_paths);

    // Create a vector to store thread handles
    let mut handles = vec![];

    // Execute each script or executable in a separate thread
    for script_path in script_paths {
        let handle = thread::spawn(move || {
            if let Err(err) = read_output_from_script(script_path) {
                eprintln!("Error executing {}: {}", script_path, err);
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to finish
    for handle in handles {
        handle.join().expect("Thread panicked")?;
    }

    Ok(())
}