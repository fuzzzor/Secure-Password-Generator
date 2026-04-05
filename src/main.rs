#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

slint::include_modules!();

use slint::Timer;
use std::rc::Rc;
use rand::Rng;
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha512;
use base64::{Engine as _, engine::general_purpose};
use arboard::Clipboard;
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::PathBuf;
use directories::ProjectDirs;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Config {
    use_upper: bool,
    use_lower: bool,
    use_digits: bool,
    use_special: bool,
    special_chars: String,
    length: f32,
    mode: String,
    theme: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            use_upper: true,
            use_lower: true,
            use_digits: true,
            use_special: false,
            special_chars: "!@#$%^&*()-_=+[]{}|;:,.<>?/".to_string(),
            length: 12.0,
            mode: "Fixed".to_string(),
            theme: "dark".to_string(),
        }
    }
}

fn get_config_path() -> Option<PathBuf> {
    if let Some(proj_dirs) = ProjectDirs::from("", "", "securepassword") {
        let config_dir = proj_dirs.config_dir();
        if !config_dir.exists() {
            let _ = fs::create_dir_all(config_dir);
        }
        return Some(config_dir.join("config.json"));
    }
    None
}

fn load_config() -> Config {
    if let Some(path) = get_config_path() {
        if let Ok(data) = fs::read_to_string(path) {
            if let Ok(config) = serde_json::from_str(&data) {
                return config;
            }
        }
    }
    Config::default()
}

fn save_config(config: &Config) {
    if let Some(path) = get_config_path() {
        if let Ok(json) = serde_json::to_string_pretty(config) {
            let _ = fs::write(path, json);
        }
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;
    let config = load_config();
    
    // Appliquer la config initiale
    ui.set_use_upper(config.use_upper);
    ui.set_use_lower(config.use_lower);
    ui.set_use_digits(config.use_digits);
    ui.set_use_special(config.use_special);
    ui.set_special_chars(config.special_chars.clone().into());
    ui.set_length(config.length);
    ui.set_mode(config.mode.clone().into());
    ui.set_theme_mode(config.theme.clone().into());
    
    // Centrer la fenêtre
    #[cfg(target_os = "windows")]
    {
        use slint::PhysicalPosition;
        
        // Attendre que la fenêtre soit affichée pour obtenir sa taille réelle
        ui.show().ok();
        
        // Obtenir les dimensions de l'écran principal (approximation pour Windows)
        let screen_width = 1920.0;
        let screen_height = 1080.0;
        
        // Obtenir la taille de la fenêtre
        let window_size = ui.window().size();
        let window_width = window_size.width as f32;
        let window_height = window_size.height as f32;
        
        // Calculer la position centrée
        let x = ((screen_width - window_width) / 2.0) as i32;
        let y = ((screen_height - window_height) / 2.0) as i32;
        
        // Positionner la fenêtre
        ui.window().set_position(PhysicalPosition::new(x, y));
    }

    let ui_handle = ui.as_weak();
    ui.on_settings_changed(move || {
        let ui = ui_handle.unwrap();
        let config = Config {
            use_upper: ui.get_use_upper(),
            use_lower: ui.get_use_lower(),
            use_digits: ui.get_use_digits(),
            use_special: ui.get_use_special(),
            special_chars: ui.get_special_chars().into(),
            length: ui.get_length(),
            mode: ui.get_mode().into(),
            theme: ui.get_theme_mode().into(),
        };
        save_config(&config);
    });

    let timer = Rc::new(Timer::default());

    let ui_handle = ui.as_weak();
    ui.on_generate_password(move || {
        let ui = ui_handle.unwrap();
        
        let use_upper = ui.get_use_upper();
        let use_lower = ui.get_use_lower();
        let use_digits = ui.get_use_digits();
        let use_special = ui.get_use_special();
        let special_chars = ui.get_special_chars();
        let length = ui.get_length() as usize;
        let mode = ui.get_mode();
        let passphrase = ui.get_passphrase();

        let mut charset = String::new();
        if use_upper { charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
        if use_lower { charset.push_str("abcdefghijklmnopqrstuvwxyz"); }
        if use_digits { charset.push_str("0123456789"); }
        if use_special { charset.push_str(&special_chars); }

        if charset.is_empty() {
            ui.set_generated_password("Error: Select at least one character type!".into());
            return;
        }

        let password = if mode == "Fixed" {
            if passphrase.is_empty() {
                ui.set_generated_password("Error: Enter a passphrase!".into());
                return;
            }
            
            // PBKDF2 avec HMAC-SHA512
            let mut key = [0u8; 64]; // 512 bits
            let iterations = 100_000;
            pbkdf2::<Hmac<Sha512>>(passphrase.as_bytes(), b"MySecurePassword", iterations, &mut key).expect("PBKDF2 failed");
            
            let hash_b64 = general_purpose::STANDARD.encode(&key);
            let charset_chars: Vec<char> = charset.chars().collect();
            let hash_chars: Vec<char> = hash_b64.chars().collect();
            
            let mut final_pass = String::new();
            // On utilise le hash pour piocher dans le charset
            for i in 0..length {
                // Si la longueur dépasse le hash, on boucle sur le hash
                let c = hash_chars[i % hash_chars.len()];
                let index = (c as usize) % charset_chars.len();
                final_pass.push(charset_chars[index]);
            }
            final_pass
        } else {
            let mut rng = rand::thread_rng();
            let charset_chars: Vec<char> = charset.chars().collect();
            (0..length)
                .map(|_| {
                    let idx = rng.gen_range(0..charset_chars.len());
                    charset_chars[idx]
                })
                .collect()
        };

        // Calcul de l'entropie
        let charset_len = charset.chars().count();
        let entropy = (length as f64) * (charset_len as f64).log2();
        
        ui.set_entropy_value((entropy / 128.0).min(1.0) as f32);
        
        let (text, r, g, b) = if entropy <= 50.0 {
            ("Weak", 255, 0, 0)
        } else if entropy <= 70.0 {
            ("Medium", 255, 165, 0)
        } else if entropy <= 90.0 {
            ("Medium High", 255, 215, 0)
        } else {
            ("Strong", 0, 128, 0)
        };
        
        ui.set_entropy_text(format!("{:.0} bits - {}", entropy, text).into());
        ui.set_entropy_color(slint::Brush::SolidColor(slint::Color::from_rgb_u8(r, g, b)));
        
        ui.set_generated_password(password.into());
        ui.set_copy_button_text("Copy".into()); // Reset text
    });

    let ui_handle = ui.as_weak();
    let timer_clone = timer.clone();
    ui.on_copy_to_clipboard(move || {
        let ui = ui_handle.unwrap();
        let password = ui.get_generated_password();
        if !password.is_empty() && !password.starts_with("Error") {
             if let Ok(mut clipboard) = Clipboard::new() {
                let _ = clipboard.set_text(password.to_string());
                
                let mut seconds = 15;
                ui.set_copy_button_text(format!("Copied! ({}s)", seconds).into());
                
                let ui_handle_timer = ui.as_weak();
                let timer_inner = timer_clone.clone();
                timer_clone.start(slint::TimerMode::Repeated, std::time::Duration::from_secs(1), move || {
                    seconds -= 1;
                    if let Some(ui) = ui_handle_timer.upgrade() {
                        if seconds > 0 {
                            ui.set_copy_button_text(format!("Copied! ({}s)", seconds).into());
                        } else {
                            ui.set_copy_button_text("Copy".into());
                            // Clear clipboard
                            if let Ok(mut clipboard) = Clipboard::new() {
                                let _ = clipboard.set_text("".to_string());
                            }
                            timer_inner.stop();
                        }
                    } else {
                        timer_inner.stop();
                    }
                });
            }
        }
    });

    let ui_handle = ui.as_weak();
    ui.on_menu_action(move |action| {
        let _ui = ui_handle.unwrap();
        match action.as_str() {
            "exit" => {
                std::process::exit(0);
            }
            _ => {}
        }
    });

    ui.run()
}
