extern crate gio;
extern crate gtk;
extern crate notify;

use gio::prelude::*;
use gtk::prelude::*;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

struct EncryptionApp {
    window: gtk::ApplicationWindow,
    directory_button: gtk::Button,
    key_button: gtk::Button,
    encrypt_trigger_menu: gtk::ComboBoxText,
    encrypt_mode_menu: gtk::ComboBoxText,
    encrypt_label: gtk::Label,
    decrypt_trigger_menu: gtk::ComboBoxText,
    decrypt_mode_menu: gtk::ComboBoxText,
    decrypt_label: gtk::Label,
    start_button: gtk::Button,
    stop_button: gtk::Button,
    created_by_label: gtk::Label,
    directory: Option<String>,
    key_file: Option<String>,
}

impl EncryptionApp {
    fn new(application: &gtk::Application) -> EncryptionApp {
        let window = gtk::ApplicationWindow::new(application);
        window.set_title("File Encryption Tool");

        let vbox = gtk::Box::new(gtk::Orientation::Vertical, 5);
        window.add(&vbox);

        let directory_button = gtk::Button::with_label("Select Directory");
        vbox.add(&directory_button);

        let key_button = gtk::Button::with_label("Select Key File");
        vbox.add(&key_button);

        let encrypt_trigger_menu = gtk::ComboBoxText::new();
        encrypt_trigger_menu.append_text("Create");
        encrypt_trigger_menu.append_text("Delete");
        encrypt_trigger_menu.append_text("Modify");
        vbox.add(&encrypt_trigger_menu);

        let encrypt_mode_menu = gtk::ComboBoxText::new();
        encrypt_mode_menu.append_text("Individual");
        encrypt_mode_menu.append_text("Group");
        encrypt_mode_menu.append_text("All");
        vbox.add(&encrypt_mode_menu);

        let encrypt_label = gtk::Label::new(None);
        vbox.add(&encrypt_label);

        let decrypt_trigger_menu = gtk::ComboBoxText::new();
        decrypt_trigger_menu.append_text("Create");
        decrypt_trigger_menu.append_text("Delete");
        decrypt_trigger_menu.append_text("Modify");
        vbox.add(&decrypt_trigger_menu);

        let decrypt_mode_menu = gtk::ComboBoxText::new();
        decrypt_mode_menu.append_text("Individual");
        decrypt_mode_menu.append_text("Group");
        decrypt_mode_menu.append_text("All");
        vbox.add(&decrypt_mode_menu);

        let decrypt_label = gtk::Label::new(None);
        vbox.add(&decrypt_label);

        let start_button = gtk::Button::with_label("Start Monitoring");
        vbox.add(&start_button);

        let stop_button = gtk::Button::with_label("Stop Monitoring");
        vbox.add(&stop_button);

        let created_by_label = gtk::Label::new(Some("Created by Blu Corbel"));
        vbox.add(&created_by_label);

        let app = EncryptionApp {
            window,
            directory_button,
            key_button,
            encrypt_trigger_menu,
            encrypt_mode_menu,
            encrypt_label,
            decrypt_trigger_menu,
            decrypt_mode_menu,
            decrypt_label,
            start_button,
            stop_button,
            created_by_label,
            directory: None,
            key_file: None,
        };

        app.connect_signals();

        app
    }

    fn connect_signals(&self) {
        let window = self.window.clone();
        let directory_button = self.directory_button.clone();
        let key_button = self.key_button.clone();
        let encrypt_trigger_menu = self.encrypt_trigger_menu.clone();
        let encrypt_mode_menu = self.encrypt_mode_menu.clone();
        let encrypt_label = self.encrypt_label.clone();
        let decrypt_trigger_menu = self.decrypt_trigger_menu.clone();
        let decrypt_mode_menu = self.decrypt_mode_menu.clone();
        let decrypt_label = self.decrypt_label.clone();
        let start_button = self.start_button.clone();
        let stop_button = self.stop_button.clone();

        directory_button.connect_clicked(move |_| {
            // Handle directory selection
        });

        key_button.connect_clicked(move |_| {
            // Handle key file selection
        });

        start_button.connect_clicked(move |_| {
            // Start monitoring
        });

        stop_button.connect_clicked(move |_| {
            // Stop monitoring
        });
    }
}

fn main() {
    gtk::init().expect("Failed to initialize GTK.");

    let application = gtk::Application::new(
        Some("com.example.fileencryptiontool"),
        gio::ApplicationFlags::FLAGS_NONE,
    )
    .expect("Failed to initialize GTK application.");

    application.connect_startup(|app| {
        let _app = EncryptionApp::new(app);
    });

    application.connect_activate(|_| {});

    application.run(&[]);
}