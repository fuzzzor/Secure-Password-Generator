import customtkinter as ctk
from CTkMessagebox import CTkMessagebox
from CTkMenuBar import *
import base64
import math
import secrets
import winsound  # Pour le bip sonore
from io import BytesIO
from PIL import Image
from customtkinter import CTkImage
from image_data import IMAGE_BASE64  # Importation de l'image encodée
from help_message import HELP_TEXT
from hashlib import pbkdf2_hmac
from tkhtmlview import HTMLLabel
from Crypto.Cipher import AES
import configparser
import os
import sys

# Configuration paths
CONFIG_DIR = os.path.join(os.environ['LOCALAPPDATA'], 'Genpass')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'genpass.ini')
CURRENT_THEME = "system"
APP_VERSION = "v1.2"

# Configuration initiale
ctk.set_appearance_mode("system")  # Mode système par défaut
ctk.set_default_color_theme("green")

# Fonction pour centrer la fenêtre principale au centre de l'écran
def center_window(Screen: ctk, width: int, height: int, scale_factor: float = 1):
    """Centers the window to the main display/monitor"""
    screen_width = Screen.winfo_screenwidth()
    screen_height = Screen.winfo_screenheight()
    x = int(((screen_width/2) - (width/2)) * scale_factor)
    y = int(((screen_height/2) - (height/1.75)) * scale_factor)
    return f"{width}x{height}+{x}+{y}"

# Creation de la fenetre principale
root = ctk.CTk()
root.title(f"Secure Password Generator {APP_VERSION}")

# Gestion de l'icône compatible avec PyInstaller --onefile
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

try:
    root.iconbitmap(resource_path("icone.ico"))
except Exception:
    pass # Si l'icone n'est pas trouvée, on continue sans

root.geometry(center_window(root, 450, 790, root._get_window_scaling()))
root.resizable(False, False)
custom_font = ctk.CTkFont(family="Bauhaus 93", size=26, weight="bold")

# Fonction pour jouer un bip sonore
def play_sound(hz, ms):
        winsound.Beep(hz, ms)  # Fréquence en Hz, durée en ms

# Fonction pour sauvegarder la configuration
def save_config():
    # Désactiver l'interpolation pour éviter l'erreur avec % dans les caractères spéciaux
    config = configparser.ConfigParser(interpolation=None)
    config['Settings'] = {
        'Theme': CURRENT_THEME,
        'SpecialChars': special_entry.get(),
        'PasswordLength': str(int(length_slider.get())),
        'UseUpper': str(var_upper.get()),
        'UseLower': str(var_lower.get()),
        'UseDigits': str(var_digits.get()),
        'UseSpecial': str(var_special.get())
    }
    
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
        
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

# Fonction pour charger la configuration
def load_config():
    global CURRENT_THEME
    
    # Créer le dossier et le fichier de config par défaut s'ils n'existent pas
    if not os.path.exists(CONFIG_DIR):
        try:
            os.makedirs(CONFIG_DIR)
        except OSError as e:
            print(f"Error creating directory {CONFIG_DIR}: {e}")
            return

    if not os.path.exists(CONFIG_FILE):
        save_config() # Crée le fichier avec les valeurs par défaut actuelles
        return

    # Désactiver l'interpolation pour la lecture aussi
    config = configparser.ConfigParser(interpolation=None)
    config.read(CONFIG_FILE)
    
    if 'Settings' in config:
        settings = config['Settings']
        
        # Theme
        theme = settings.get('Theme', 'system')
        set_theme(theme, save=False)
        
        # Length
        length = settings.get('PasswordLength', '12')
        try:
            length_val = int(length)
            length_var.set(str(length_val)) # Force string
            length_slider.set(length_val)
            length_label.configure(text=f"Length : {length_val}")
        except ValueError:
            pass
        
        # Upper/Lower/Digits/Special
        var_upper.set(settings.getboolean('UseUpper', fallback=True))
        var_lower.set(settings.getboolean('UseLower', fallback=True))
        var_digits.set(settings.getboolean('UseDigits', fallback=True))
        var_special.set(settings.getboolean('UseSpecial', fallback=False))

        # Special Chars content
        special_chars = settings.get('SpecialChars', "!@#$%^&*()-_=+[]{}|;:,.<>?/")
        
        special_entry.configure(state="normal")
        special_entry.delete(0, "end")
        special_entry.insert(0, special_chars)
        
        # Update special_entry state based on var_special
        if var_special.get():
             special_entry.configure(state="normal", text_color="white", fg_color="gray20")
        else:
             special_entry.configure(state="disabled", text_color="white", fg_color="gray15")

# Fonction pour mettre à jour les coches du menu thème
def update_theme_checks():
    try:
        # Reset texts
        btn_light.configure(text="Light")
        btn_dark.configure(text="Dark")
        btn_system.configure(text="System")
        
        if CURRENT_THEME == "light":
            btn_light.configure(text="Light   ✓")
        elif CURRENT_THEME == "dark":
            btn_dark.configure(text="Dark   ✓")
        elif CURRENT_THEME == "system":
            btn_system.configure(text="System   ✓")
    except NameError:
        pass # Les boutons ne sont pas encore créés

# Fonction pour changer le thème
def set_theme(theme, save=True):
    global CURRENT_THEME
    CURRENT_THEME = theme
    ctk.set_appearance_mode(theme)
    if save:
        save_config()
    update_theme_checks()

# Fonction pour calculer l'entropie du mot de passe
def calculate_entropy(password_length, charset_size):
    entropy = password_length * math.log2(charset_size)
    if var_special.get():  # Bonus si caractères spéciaux
        entropy += 15
    if var_upper.get() and var_lower.get() and var_digits.get(): # Bonus si mix complet
        entropy += 10
    return entropy

# Fonction pour mettre à jour la progressbar d'entropie et le texte
def update_entropy_bar(password):
    charset_size = 0
    if var_upper.get():
        charset_size += 26
    if var_lower.get():
        charset_size += 26
    if var_digits.get():
        charset_size += 10
    if var_special.get():
        charset_size += len("!@#$%^&*()-_=+[]{}|;:,.<>?/")

    if charset_size == 0:
        entropy = 0
    else:
        entropy = calculate_entropy(len(password), charset_size)

    # Définir le niveau de sécurité en fonction de l'entropie
    if entropy <= 50:
        color = "red"
        strength_text = f"{int(entropy)} bits - Weak"
        progress_value = 0.2
        progress_color = "red"
    elif entropy <= 70:
        color = "orange"
        strength_text = f"{int(entropy)} bits - Medium"
        progress_value = 0.5
        progress_color = "orange"
    elif entropy <= 90:
        color = "#FFD700" # Gold
        strength_text = f"{int(entropy)} bits - Medium High"
        progress_value = 0.75
        progress_color = "#FFD700"
    else:
        color = "green"
        strength_text = f"{int(entropy)} bits - Strong"
        progress_value = 1.0
        progress_color = "green"

    # Mettre à jour la barre de progression et la couleur de la barre
    entropy_progress.set(progress_value)
    entropy_bar.configure(progress_color=progress_color)
    strength_label.configure(text=strength_text, text_color=color)  # Changer la couleur du texte

# Fonction pour générer le mot de passe
def generate_password():
    #play_sound(200,100) # Fréquence 100 Hz, durée 300 ms
    winsound.MessageBeep(winsound.MB_ICONASTERISK)
    passphrase = passphrase_entry.get()
    length = int(length_var.get())
    selected_option = mode_var.get()

    if not passphrase and selected_option != "Random":
        msg_box = CTkMessagebox(title="Warning", message="Passphrase not present. Enter your passphrase...",icon="warning", option_1="Okay",width=400, height=200)
        msg_box.geometry("+{}+{}".format(root.winfo_x() + (root.winfo_width() // 2) - (400 // 2), root.winfo_y() + (root.winfo_height() // 2) - (200 // 2)))
        return

    charset = ""
    if var_upper.get():
        charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if var_lower.get():
        charset += "abcdefghijklmnopqrstuvwxyz"
    if var_digits.get():
        charset += "0123456789"
    if var_special.get():
        charset += special_entry.get()

    if not charset and selected_option == "Random":
        msg_box = CTkMessagebox(title="Warning", message="Select at least one character type!",icon="warning", option_1="Okay",width=400, height=200)
        msg_box.geometry("+{}+{}".format(root.winfo_x() + (root.winfo_width() // 2) - (400 // 2), root.winfo_y() + (root.winfo_height() // 2) - (200 // 2)))
        return

    password = ""
    if selected_option == "Fixed":
        secret_key = passphrase.encode()
        hash_bytes = pbkdf2_hmac("sha512", secret_key, b"MySecurePassword", iterations=100000, dklen=96)
        hash_b64 = base64.b64encode(hash_bytes).decode()
        # Utilise le hash pour créer un mot de passe déterministe
        password = "".join(charset[ord(c) % len(charset)] for c in hash_b64)[:length]

    else:  # Mode "Random"
        password = "".join(secrets.choice(charset) for _ in range(length))

    result_entry.configure(state="normal")
    result_entry.delete(1.0, "end")
    result_entry.insert("end", password)
    result_entry.configure(state="disabled")
 
    # Mettre à jour l'entropie
    update_entropy_bar(password)

# Fonction pour copier dans le presse-papier
def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(result_entry.get("1.0", "end-1c"))
    countdown(15)  # Lancer le compteur à 10 secondes
    copy_button.configure(text="Copied!")

# Fonction compteur pour copy
def countdown(seconds):
    if seconds > 0:
        copy_button.configure(text=f"Copied! ({seconds}s)")
        root.after(1500, lambda: countdown(seconds - 1))  # Attendre 1 seconde et décrémenter
    else:
        copy_button.configure(text="Copy")
        play_sound(300,100) # Fréquence 300 Hz, durée 100 ms
        clear_clipboard()  # Vider le presse-papier à la fin du compte à rebours

# Fonction pour supprimer le presse-papier
def clear_clipboard(): 
    root.clipboard_clear()  # Tente de vider le presse-papier
    root.clipboard_append("")  # Ajoute un espace vide pour contourner les restrictions
    root.update()  # Force la mise à jour du presse-papier

# Fonction pour mettre à jour le label du slider
def update_slider_label(value):
    val = int(value)
    length_var.set(val)
    length_label.configure(text=f"Length : {val}")
    # On ne sauvegarde pas la config ici pour éviter trop d'écritures pendant le glissement
    # On préfère sauvegarder quand l'utilisateur relâche le slider ou quitte

# Fonction appelée quand on relâche le slider
def on_slider_release(event):
    save_config()

# Affiche ou masque la passphrase
def toggle_passphrase():
    if show_passphrase_var.get():
        passphrase_entry.configure(show="")  # Afficher la passphrase
        try:
             eye_btn.configure(fg_color="#2FA572")
        except NameError:
             pass
    else:
        passphrase_entry.configure(show="•")  # Masquer avec des étoiles
        try:
             eye_btn.configure(fg_color="gray30")
        except NameError:
             pass

# Fonction pour quitter l'application
def exit_app():
    root.quit()

# Fonction pour détecter la touche "Entrée" et générer le mot de passe
def on_enter(event):
    generate_password()

# Fonction pour About
def about_app():
    msg_box = CTkMessagebox(title="About...", message=f"Secure Password Generator {APP_VERSION}\n\n" "This freeware is coded in python v3.\n\n" "You can use this freeware and distribute it without any limitation !\n\n""Created by Stéphane Dudez 2006-2025",icon="check", option_1="Thanks", sound=True,height=100,width=500, justify="center")
    msg_box.geometry("+{}+{}".format(root.winfo_x() + (root.winfo_width() // 2) - (400 // 2), root.winfo_y() + (root.winfo_height() // 2) - (200 // 2)))  # Ajuste les dimensions de la messagebox

# Fonction pour la fenetre Help
def help_app():
    window_help_width = 500
    window_help_height = 650
    help_window = ctk.CTkToplevel(root)
    #help_window.geometry(f"{window_help_width}x{window_help_height}")
    help_window.geometry("+{}+{}".format(root.winfo_x() + (root.winfo_width() // 2) - (500 // 2), root.winfo_y() + (help_window.winfo_height() // 2) - (630 // 2)))
    help_window.resizable(False, False)
    help_window.title("Help...")
    help_window.grab_set()
    html_label = HTMLLabel(help_window, html=HELP_TEXT,font=("Trebuchet MS Italique", 14))
    html_label.pack(fill="both", expand=False)
    html_label.fit_height()
    close_button = ctk.CTkButton(help_window, text="Close", command=help_window.destroy)
    close_button.pack(pady=10)
    

# Toggle entry
def toggle_specialentry():
    if var_special.get():  # Si ON (valeur 1)
        special_entry.configure(state="normal", text_color="white", fg_color="gray20")
    else:  # Si OFF (valeur 0)
        special_entry.configure(state="disabled", text_color="white", fg_color="gray15")
    save_config()

# Vérifie les boutons radios
def check_radio():
    if mode_var.get() == "Random":
        passphrase_entry.delete(0, "end")
        passphrase_entry.configure(state="disabled",text_color="white", fg_color="gray15")
    else:
        passphrase_entry.configure(state="normal",text_color="white", fg_color="gray20")

# MenuBar
menu = CTkMenuBar(root,bg_color="transparent")
Menu_1 = menu.add_cascade("Options")
Menu_2 = menu.add_cascade("?")
# Menu 1
dropdown1 = CustomDropdownMenu(widget=Menu_1)
show_passphrase_var = ctk.BooleanVar(value=False)
dropdown1.add_option(option="Show/hide passphrase", command=lambda: [show_passphrase_var.set(not show_passphrase_var.get()), toggle_passphrase()])
# Sous menu
sub_menu = dropdown1.add_submenu("Theme")
btn_light = sub_menu.add_option(option="Light", command=lambda: set_theme("light"))
btn_dark = sub_menu.add_option(option="Dark", command=lambda: set_theme("dark"))
btn_system = sub_menu.add_option(option="System", command=lambda: set_theme("system"))
dropdown1.add_separator()
dropdown1.add_option(option="Exit", command=exit_app)
# Menu 2
dropdown2 = CustomDropdownMenu(widget=Menu_2)
dropdown2.add_option(option="Help",command=help_app)
dropdown2.add_option(option="About...",command=about_app)

# 1. Zone Passphrase
passphrase_frame = ctk.CTkFrame(root)
passphrase_frame.pack(fill="x", padx=10, pady=(2, 10))

ctk.CTkLabel(passphrase_frame, text="Passphrase :",text_color="#FF5733").pack(pady=(10, 0))

passphrase_entry_container = ctk.CTkFrame(passphrase_frame, fg_color="transparent")
passphrase_entry_container.pack(pady=10)

passphrase_entry = ctk.CTkEntry(passphrase_entry_container, justify="center", width=260, show="•", height=35)
passphrase_entry.pack(side="left", padx=(0, 5))
passphrase_entry.configure(state="normal")

def toggle_eye():
    if show_passphrase_var.get():
        show_passphrase_var.set(False)
        eye_btn.configure(fg_color="gray30")
    else:
        show_passphrase_var.set(True)
        eye_btn.configure(fg_color="#2FA572") # Même vert que la bordure
    toggle_passphrase()

eye_btn = ctk.CTkButton(passphrase_entry_container, text="👁", width=35, height=35, command=toggle_eye, fg_color="gray30")
eye_btn.pack(side="left")

# Initialisation de l'icône de l'œil
if show_passphrase_var.get():
    eye_btn.configure(fg_color="#2FA572")
else:
    eye_btn.configure(fg_color="gray30")

# 2. Zone Options (Switches + Image + Length + SpecialChars)
options_frame = ctk.CTkFrame(root)
options_frame.pack(fill="x", padx=10, pady=5)

# Container pour switches et image
top_options_frame = ctk.CTkFrame(options_frame, fg_color="transparent")
top_options_frame.pack(fill="x", pady=5)

# Décoder et charger l'image
image_data = base64.b64decode(IMAGE_BASE64)
image_pil = Image.open(BytesIO(image_data))
image_ctk = CTkImage(light_image=image_pil, dark_image=image_pil, size=(120, 120))

var_upper = ctk.BooleanVar(value=True)
var_lower = ctk.BooleanVar(value=True)
var_digits = ctk.BooleanVar(value=True)
var_special = ctk.BooleanVar(value=False)

switch_frame = ctk.CTkFrame(top_options_frame, fg_color="transparent")
switch_frame.pack(side="left", padx=20)

ctk.CTkSwitch(switch_frame, text="Uppercase", variable=var_upper, command=save_config).pack(anchor="w", pady=2)
ctk.CTkSwitch(switch_frame, text="Lowercase", variable=var_lower, command=save_config).pack(anchor="w", pady=2)
ctk.CTkSwitch(switch_frame, text="Numbers", variable=var_digits, command=save_config).pack(anchor="w", pady=2)
ctk.CTkSwitch(switch_frame, text="Special characters", variable=var_special,command=toggle_specialentry).pack(anchor="w", pady=2)

# Image à droite
image_label = ctk.CTkLabel(top_options_frame, image=image_ctk,text="")
image_label.pack(side="right", padx=20)
text_label = ctk.CTkLabel(image_label, text="Password Generator", font=custom_font, text_color="#2FA572", fg_color="transparent",wraplength=128,justify="center") 
text_label.place(relx=0.5, rely=0.36, anchor="center")

# Entry pour caractères spéciaux
special_entry = ctk.CTkEntry(options_frame, state="disabled", width=200, show=())
special_entry.pack(padx=25, pady=(0, 10), anchor="w")

# Initialisation
special_entry.configure(state="normal")
special_entry.insert(0, "!@#$%^&*()-_=+[]{}|;:,.<>?/")
special_entry.configure(state="disabled", text_color="white", fg_color="gray15")
special_entry.bind("<KeyRelease>", lambda event: save_config())

# Slider longueur
length_var = ctk.StringVar(value="12")
length_label = ctk.CTkLabel(options_frame, text_color="#FF5733", text=f"Length : {length_var.get()}")
length_label.pack(pady=0)
length_slider = ctk.CTkSlider(options_frame, from_=3, to=128, number_of_steps=125, command=update_slider_label,height=25,width=250)
length_slider.set(12)
length_slider.bind("<ButtonRelease-1>", on_slider_release) # Sauvegarder au relâchement
length_slider.pack(pady=(0, 10))


# 3. Zone Mode
mode_frame = ctk.CTkFrame(root)
mode_frame.pack(fill="x", padx=10, pady=10)

mode_var = ctk.StringVar(value="Fixed")
ctk.CTkLabel(mode_frame, text="Mode :",text_color="#FF5733").pack(pady=5)
radio_container = ctk.CTkFrame(mode_frame, fg_color="transparent")
radio_container.pack(pady=(0, 10))
radio1=ctk.CTkRadioButton(radio_container, text="Fixed", variable=mode_var, value="Fixed",command=check_radio).pack(side="left", padx=30)
radio2=ctk.CTkRadioButton(radio_container, text="Random", variable=mode_var, value="Random",command=check_radio).pack(side="left", padx=30)


# 4. Zone Resultat (Zone de texte pour le mot de passe + boutons)
result_area_frame = ctk.CTkFrame(root)
result_area_frame.pack(fill="x", padx=10, pady=10)

ctk.CTkLabel(result_area_frame, text="Password :", text_color="#FF5733").pack(pady=(10, 0))

border_frame = ctk.CTkFrame(result_area_frame, fg_color="#2FA572", corner_radius=6)
border_frame.pack(pady=10)
result_entry = ctk.CTkTextbox(border_frame, width=320, height=80, fg_color="grey", text_color="black", state="disabled",corner_radius=5)
result_entry.pack(pady=10)

# Barre de progression pour l'entropie
entropy_progress = ctk.DoubleVar()
entropy_bar = ctk.CTkProgressBar(result_area_frame, variable=entropy_progress, width=280)
entropy_bar.pack(pady=10)
strength_label = ctk.CTkLabel(result_area_frame, text="Security level : ",text_color="#FF5733")
strength_label.pack(pady=(0, 5))

# Cadre pour les boutons sur la même ligne
button_frame = ctk.CTkFrame(result_area_frame,fg_color="transparent")
button_frame.pack(pady=15)

# Bouton generate et Copy
generate_button = ctk.CTkButton(button_frame, text="Generate", command=generate_password,height=50, width=160, font=("Roboto", 16, "bold"))
generate_button.pack(side="left", padx=10)
copy_button = ctk.CTkButton(button_frame, text="Copy", command=copy_to_clipboard,height=50,width=120, font=("Roboto", 16, "bold"))
copy_button.pack(side="left", padx=10)

# Lier la touche "Entrée" à la fonction `on_enter` pour générer le mot de passe
root.bind('<Return>', on_enter)

# Charger la configuration au démarrage
load_config()
update_theme_checks()

root.mainloop()
