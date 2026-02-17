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

# Configuration initiale
ctk.set_appearance_mode("dark")  # Mode sombre par défaut
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
root.title("Secure Password Generator v1.0")
root.geometry(center_window(root, 400, 630, root._get_window_scaling()))
root.resizable(False, False)
custom_font = ctk.CTkFont(family="Bauhaus 93", size=26, weight="bold")

# Fonction pour jouer un bip sonore
def play_sound(hz, ms):
        winsound.Beep(hz, ms)  # Fréquence en Hz, durée en ms

# Fonction pour changer le thème
def set_theme(theme):
    ctk.set_appearance_mode(theme)

# Fonction pour calculer l'entropie du mot de passe
def calculate_entropy(password_length, charset_size):
    if var_special.get():  # Ajouter 16 bits si caractères spéciaux activés
        entropy = (password_length * math.log2(charset_size)) + 16
    else:
        entropy = password_length * math.log2(charset_size)
    return entropy

# Fonction pour mettre à jour la progressbar d'entropie et le texte
def update_entropy_bar(password):
    if mode_var.get() == "AES":
        strength_label.configure(text="AES-256 Encrypted", text_color="#00AFFF")
        entropy_progress.set(1.0)
        entropy_bar.configure(progress_color="#00AFFF")
        return

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
        progress_value = 0.3
        progress_color = "red"
    elif entropy <= 90:
        color = "orange"
        strength_text = f"{int(entropy)} bits - Medium"
        progress_value = 0.6
        progress_color = "orange"
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
# Fonction pour déchiffrer le mot de passe (uniquement pour le mode AES)
def decrypt_password():
    passphrase = passphrase_entry.get()
    encrypted_data_b64 = result_entry.get("1.0", "end-1c")

    if not passphrase:
        msg_box = CTkMessagebox(title="Warning", message="Passphrase is required for decryption.", icon="warning")
        msg_box.geometry("+{}+{}".format(root.winfo_x() + (root.winfo_width() // 2) - (400 // 2), root.winfo_y() + (root.winfo_height() // 2) - (200 // 2)))
        return
    
    try:
        # Décoder depuis base64
        encrypted_data = base64.b64decode(encrypted_data_b64)

        # Extraire le nonce, le tag et le texte chiffré
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        # Dériver la même clé
        salt = b'salt_for_aes_123' # Doit être le même que celui utilisé pour le chiffrement
        key = pbkdf2_hmac('sha256', passphrase.encode('utf-8'), salt, 100000, dklen=32)

        # Déchiffrer et vérifier
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_password = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

        # Afficher le résultat
        msg_box = CTkMessagebox(title="Decrypted Password", message=f"Decrypted password:\n\n{decrypted_password}", icon="check")
        msg_box.geometry("+{}+{}".format(root.winfo_x() + (root.winfo_width() // 2) - (400 // 2), root.winfo_y() + (root.winfo_height() // 2) - (200 // 2)))

    except (ValueError, KeyError):
        msg_box = CTkMessagebox(title="Error", message="Decryption failed. Check the passphrase or data.", icon="cancel")
        msg_box.geometry("+{}+{}".format(root.winfo_x() + (root.winfo_width() // 2) - (400 // 2), root.winfo_y() + (root.winfo_height() // 2) - (200 // 2)))

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

    elif selected_option == "AES":
        # 1. Générer un mot de passe aléatoire à chiffrer
        if not charset: # Si aucun jeu de caractères n'est sélectionné, en créer un par défaut
            charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        
        password_to_encrypt = "".join(secrets.choice(charset) for _ in range(length))

        # 2. Dériver une clé de 256 bits à partir de la passphrase
        salt = b'salt_for_aes_123' # Dans une vraie application, ce sel devrait être aléatoire et stocké
        key = pbkdf2_hmac('sha256', passphrase.encode('utf-8'), salt, 100000, dklen=32)

        # 3. Chiffrer le mot de passe avec AES en mode GCM
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(password_to_encrypt.encode('utf-8'))

        # 4. Combiner nonce, tag et texte chiffré, puis encoder en base64
        password = base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

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
    play_sound(300,100) # Fréquence 200 Hz, durée 100 ms
    copy_button.configure(text="Copied!")

# Fonction compteur pour copy
def countdown(seconds):
    if seconds > 0:
        copy_button.configure(text=f"Copied! ({seconds}s)")
        root.after(1500, lambda: countdown(seconds - 1))  # Attendre 1 seconde et décrémenter
    else:
        copy_button.configure(text="Copy")
        clear_clipboard()  # Vider le presse-papier à la fin du compte à rebours

# Fonction pour supprimer le presse-papier
def clear_clipboard(): 
    root.clipboard_clear()  # Tente de vider le presse-papier
    root.clipboard_append("")  # Ajoute un espace vide pour contourner les restrictions
    root.update()  # Force la mise à jour du presse-papier

# Fonction pour mettre à jour le label du slider
def update_slider_label(value):
    length_var.set(int(value))
    length_label.configure(text=f"Length : {int(value)}")

# Affiche ou masque la passphrase
def toggle_passphrase():
    if show_passphrase_var.get():
        passphrase_entry.configure(show="")  # Afficher la passphrase
    else:
        passphrase_entry.configure(show="•")  # Masquer avec des étoiles

# Fonction pour quitter l'application
def exit_app():
    root.quit()

# Fonction pour détecter la touche "Entrée" et générer le mot de passe
def on_enter(event):
    generate_password()

# Fonction pour About
def about_app():
    msg_box = CTkMessagebox(title="About...", message="Secure Password Generator v1.0\n\n" "This freeware is recoded in python v3.\n\n" "You can use this freeware and distribute it without any limitation !\n\n""Created by Stéphane Dudez 2006-2025",icon="check", option_1="Thanks", sound=True,height=100,width=500, justify="center")
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
sub_menu.add_option(option="Light", command=lambda: set_theme("light"))
sub_menu.add_option(option="Dark", command=lambda: set_theme("dark"))
dropdown1.add_separator()
dropdown1.add_option(option="Exit", command=exit_app)
# Menu 2
dropdown2 = CustomDropdownMenu(widget=Menu_2)
dropdown2.add_option(option="Help",command=help_app)
dropdown2.add_option(option="About...",command=about_app)

# Widgets principaux
ctk.CTkLabel(root, text="Passphrase :",text_color="#FF5733").pack(pady=5)
passphrase_entry = ctk.CTkEntry(root, justify="center", width=250, show="•")
passphrase_entry.pack(pady=5)
passphrase_entry.configure(state="normal")

length_var = ctk.StringVar(value="12")
length_label = ctk.CTkLabel(root, text_color="#FF5733", text=f"Lenght : {length_var.get()}")
length_label.pack(pady=5)
length_slider = ctk.CTkSlider(root, from_=3, to=128, number_of_steps=126, command=update_slider_label,height=25,width=250)
length_slider.set(12)
length_slider.pack(pady=5)

# Décoder et charger l'image
image_data = base64.b64decode(IMAGE_BASE64)
image_pil = Image.open(BytesIO(image_data))#.resize((200, 200))  # Redimension à 200x200
image_ctk = CTkImage(light_image=image_pil, dark_image=image_pil, size=(120, 120))

# Ajouter les switches et l'image
frame = ctk.CTkFrame(root,fg_color="transparent")
frame.pack(pady=10)

var_upper = ctk.BooleanVar(value=True)
var_lower = ctk.BooleanVar(value=True)
var_digits = ctk.BooleanVar(value=True)
var_special = ctk.BooleanVar(value=False)
# frame
switch_frame = ctk.CTkFrame(frame,fg_color="transparent")
switch_frame.pack(side="left", padx=40)

ctk.CTkSwitch(switch_frame, text="Uppercase", variable=var_upper).pack(anchor="w", pady=2)
ctk.CTkSwitch(switch_frame, text="Lowercase", variable=var_lower).pack(anchor="w", pady=2)
ctk.CTkSwitch(switch_frame, text="Numbers", variable=var_digits).pack(anchor="w", pady=2)
ctk.CTkSwitch(switch_frame, text="Special characters", variable=var_special,command=toggle_specialentry).pack(anchor="w", pady=2)

# Ajout de l'image et le texte à droite des switches
image_label = ctk.CTkLabel(frame, image=image_ctk,text="")#, font=custom_font, text_color="#FF5733", text="",wraplength=128, justify="center")
image_label.pack(side="right")
text_label = ctk.CTkLabel(image_label, text="Password Generator", font=custom_font, text_color="#2FA572", fg_color="transparent",wraplength=128,justify="center") 
text_label.place(relx=0.5, rely=0.36, anchor="center")

# Ajout de l'entrée des caractères spéciaux
special_entry = ctk.CTkEntry(root, state="disabled", width=200, show=()) 
special_entry.pack(padx=50, pady=0, anchor="w")
special_entry.configure(state="normal")
special_entry.insert(0, "!@#$%^&*()-_=+[]{}|;:,.<>?/")  #!@#$%^&*()-_=+[]{}|;:,.<>?/
special_entry.configure(state="disabled",text_color="white", fg_color="gray15")

# Ajout des boutons radios
mode_var = ctk.StringVar(value="Fixed")
ctk.CTkLabel(root, text="Mode :",text_color="#FF5733").pack(pady=5)
radio_frame = ctk.CTkFrame(root,fg_color="transparent")
radio_frame.pack(pady=5)
radio1=ctk.CTkRadioButton(radio_frame, text="Fixed", variable=mode_var, value="Fixed",command=check_radio).pack(side="left", padx=10)
radio2=ctk.CTkRadioButton(radio_frame, text="Random", variable=mode_var, value="Random",command=check_radio).pack(side="left", padx=10)
radio3=ctk.CTkRadioButton(radio_frame, text="AES", variable=mode_var, value="AES",command=check_radio).pack(side="left", padx=10)

# Zone de texte pour le mot de passe
border_frame = ctk.CTkFrame(root, fg_color="#2FA572", corner_radius=6)
border_frame.pack(pady=5)
result_entry = ctk.CTkTextbox(border_frame, width=280, height=70, fg_color="grey", text_color="black", state="disabled",corner_radius=5)
result_entry.pack(pady=5)

# Barre de progression pour l'entropie
entropy_progress = ctk.DoubleVar()
entropy_bar = ctk.CTkProgressBar(root, variable=entropy_progress, width=250)
entropy_bar.pack(pady=5)
strength_label = ctk.CTkLabel(root, text="Security level : ",text_color="#FF5733")
strength_label.pack()

# Cadre pour les boutons sur la même ligne
button_frame = ctk.CTkFrame(root,fg_color="transparent")
button_frame.pack(pady=10)

# Bouton generate et Copy
generate_button = ctk.CTkButton(button_frame, text="Generate", command=generate_password,height=40)
generate_button.pack(side="left", padx=5)
decrypt_button = ctk.CTkButton(button_frame, text="Decrypt", command=decrypt_password, height=40)
decrypt_button.pack(side="left", padx=5)
copy_button = ctk.CTkButton(button_frame, text="Copy", command=copy_to_clipboard,height=40,width=50)
copy_button.pack(side="left", padx=10)

# Lier la touche "Entrée" à la fonction `on_enter` pour générer le mot de passe
root.bind('<Return>', on_enter)
root.mainloop()
