use gtk::prelude::*;
use gtk::{Button, Window, WindowType};

fn main() {
    // Initialize GTK application
    gtk::init().expect("Failed to initialize GTK.");

    // Create main window
    let window = Window::new(WindowType::Toplevel);
    window.set_title("Cybersecurity Tool");
    window.set_default_size(400, 400);

    // Create buttons for each function
    let button_threat_intelligence = Button::new_with_label("Threat Intelligence");
    let button_vulnerability_assessment = Button::new_with_label("Vulnerability Assessment");
    let button_penetration_testing = Button::new_with_label("Penetration Testing");
    let button_intrusion_detection = Button::new_with_label("Intrusion Detection");
    let button_data_protection = Button::new_with_label("Data Protection");
    let button_incident_response = Button::new_with_label("Incident Response");
    let button_endpoint_security = Button::new_with_label("Endpoint Security");
    let button_monitoring_siem = Button::new_with_label("Monitoring and SIEM");
    let button_continuous_monitoring = Button::new_with_label("Continuous Monitoring");
    let button_reporting = Button::new_with_label("Reporting");
    let button_compliance = Button::new_with_label("Compliance");

    // Connect signals for each button
    button_threat_intelligence.connect_clicked(|_| {
        show_instructions("Threat Intelligence", "Instructions for Threat Intelligence:\n\n1. Gather information from various sources to identify potential cybersecurity threats.\n2. Analyze malware samples, query threat intelligence feeds, etc.");
    });

    button_vulnerability_assessment.connect_clicked(|_| {
        show_instructions("Vulnerability Assessment", "Instructions for Vulnerability Assessment:\n\n1. Scan the target system for potential vulnerabilities using tools like Nessus or OpenVAS.\n2. Analyze scan results and prioritize vulnerabilities for remediation.");
    });

    // Add more buttons and connect signals here...

    // Add buttons to the window
    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 5);
    vbox.pack_start(&button_threat_intelligence, true, true, 0);
    vbox.pack_start(&button_vulnerability_assessment, true, true, 0);
    vbox.pack_start(&button_penetration_testing, true, true, 0);
    vbox.pack_start(&button_intrusion_detection, true, true, 0);
    vbox.pack_start(&button_data_protection, true, true, 0);
    vbox.pack_start(&button_incident_response, true, true, 0);
    vbox.pack_start(&button_endpoint_security, true, true, 0);
    vbox.pack_start(&button_monitoring_siem, true, true, 0);
    vbox.pack_start(&button_continuous_monitoring, true, true, 0);
    vbox.pack_start(&button_reporting, true, true, 0);
    vbox.pack_start(&button_compliance, true, true, 0);

    window.add(&vbox);

    // Show everything
    window.show_all();

    // Start the GTK main event loop
    gtk::main();
}

// Function to show text-based instructions in a separate window
fn show_instructions(title: &str, instructions: &str) {
    // Create a new window
    let window = Window::new(WindowType::Toplevel);
    window.set_title(title);
    window.set_default_size(400, 300);

    // Create label with instructions
    let label = gtk::Label::new(Some(instructions));

    // Add label to the window
    window.add(&label);

    // Show window
    window.show_all();
}