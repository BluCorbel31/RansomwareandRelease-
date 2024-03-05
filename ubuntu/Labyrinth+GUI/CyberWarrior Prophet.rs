use std::fs::OpenOptions;
use std::io::{Write, Error};

// Define types of alerts
#[derive(Debug)]
enum Alert {
    Login(String),
    Error(String),
    Attack(String),
    Update(String),
    // Add more alert types as needed
}

fn main() {
    // Simulate receiving alerts (can be replaced with actual event sources)
    let alerts = vec![
        Alert::Login("Successful login from 192.168.1.100".to_string()),
        Alert::Error("500 Internal Server Error".to_string()),
        Alert::Attack("SQL injection attempt detected".to_string()),
        Alert::Update("Software update available: Version 2.0".to_string()),
    ];

    // Process alerts and log them
    for alert in alerts {
        if let Err(err) = log_alert(&alert) {
            eprintln!("Failed to log alert: {}", err);
        }
    }
}

fn log_alert(alert: &Alert) -> Result<(), Error> {
    // Open or create a log file for appending
    let mut file = OpenOptions::new().create(true).append(true).open("siem.log")?;

    // Get current timestamp
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    // Format and write alert to the log file
    let message = match alert {
        Alert::Login(msg) => format!("[{}] [LOGIN] {}", timestamp, msg),
        Alert::Error(msg) => format!("[{}] [ERROR] {}", timestamp, msg),
        Alert::Attack(msg) => format!("[{}] [ATTACK] {}", timestamp, msg),
        Alert::Update(msg) => format!("[{}] [UPDATE] {}", timestamp, msg),
    };

    writeln!(file, "{}", message)?;

    Ok(())
}