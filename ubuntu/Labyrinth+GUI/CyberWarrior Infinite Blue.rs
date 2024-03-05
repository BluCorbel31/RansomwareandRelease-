use std::process::Command;

fn main() {
    // Define VM IP addresses or hostnames
    let vm1_ip = "192.168.1.101";
    let vm2_ip = "192.168.1.102";
    let target_ip = "192.168.1.200";

    // Execute vulnerability assessment on VMs
    let vm1_output = execute_vulnerability_assessment(vm1_ip, target_ip);
    let vm2_output = execute_vulnerability_assessment(vm2_ip, target_ip);

    // Search for keywords in the output
    search_keywords_in_output(vm1_output);
    search_keywords_in_output(vm2_output);
}

fn execute_vulnerability_assessment(vm_ip: &str, target_ip: &str) -> String {
    // Example: Execute vulnerability assessment on a VM and return output
    let output = Command::new("ssh")
        .arg(format!("user@{}", vm_ip))
        .arg("nessus")
        .arg("--target")
        .arg(target_ip)
        .output()
        .expect("Failed to execute vulnerability assessment on VM.");
    
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn search_keywords_in_output(output: String) {
    // Define keywords to search for
    let keywords = vec!["vulnerability", "exploit", "risk", "severity"];

    // Search for keywords in the output
    for keyword in keywords {
        if output.contains(keyword) {
            println!("Keyword '{}' found in the output:", keyword);
            println!("{}", output);
            println!("-------------------");
        }
    }
}