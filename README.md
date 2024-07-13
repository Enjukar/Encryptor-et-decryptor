Étape 1 : Installation des dépendances
Installez les bibliothèques nécessaires :

pip install pycryptodome
pip install pyinstaller

Étape 2 : Script Python

Voici le script Python pour chiffrer et déchiffrer des fichiers et des dossiers en utilisant deux mots de passe avec AES-256 :

import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Fonction pour dériver une clé AES à partir de deux mots de passe
def derive_key(password1, password2, salt):
    combined_password = password1 + password2
    key = PBKDF2(combined_password, salt, dkLen=32)
    return key

# Fonction pour chiffrer un fichier
def encrypt_file(file_path, password1, password2):
    salt = get_random_bytes(16)
    key = derive_key(password1, password2, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce

    with open(file_path, 'rb') as f:
        data = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + nonce + tag + ciphertext)

    os.remove(file_path)
    messagebox.showinfo("Succès", "Le fichier a été chiffré avec succès!")

# Fonction pour déchiffrer un fichier
def decrypt_file(file_path, password1, password2):
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    key = derive_key(password1, password2, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
        original_file_path = file_path[:-4]

        with open(original_file_path, 'wb') as f:
            f.write(data)

        os.remove(file_path)
        messagebox.showinfo("Succès", "Le fichier a été déchiffré avec succès!")
    except ValueError:
        messagebox.showerror("Erreur", "Les mots de passe sont incorrects ou le fichier est corrompu.")

# Fonction pour sélectionner un fichier à chiffrer
def select_file_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        password1 = password1_entry.get()
        password2 = password2_entry.get()
        if password1 and password2:
            encrypt_file(file_path, password1, password2)
        else:
            messagebox.showerror("Erreur", "Veuillez entrer les deux mots de passe.")

# Fonction pour sélectionner un fichier à déchiffrer
def select_file_decrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        password1 = password1_entry.get()
        password2 = password2_entry.get()
        if password1 and password2:
            decrypt_file(file_path, password1, password2)
        else:
            messagebox.showerror("Erreur", "Veuillez entrer les deux mots de passe.")

# Fonction pour chiffrer un dossier
def encrypt_folder(folder_path, password1, password2):
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, password1, password2)

# Fonction pour déchiffrer un dossier
def decrypt_folder(folder_path, password1, password2):
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.enc'):
                file_path = os.path.join(root, file)
                decrypt_file(file_path, password1, password2)

# Fonction pour sélectionner un dossier à chiffrer
def select_folder_encrypt():
    folder_path = filedialog.askdirectory()
    if folder_path:
        password1 = password1_entry.get()
        password2 = password2_entry.get()
        if password1 and password2:
            encrypt_folder(folder_path, password1, password2)
        else:
            messagebox.showerror("Erreur", "Veuillez entrer les deux mots de passe.")

# Fonction pour sélectionner un dossier à déchiffrer
def select_folder_decrypt():
    folder_path = filedialog.askdirectory()
    if folder_path:
        password1 = password1_entry.get()
        password2 = password2_entry.get()
        if password1 and password2:
            decrypt_folder(folder_path, password1, password2)
        else:
            messagebox.showerror("Erreur", "Veuillez entrer les deux mots de passe.")

# Interface utilisateur
root = tk.Tk()
root.title("Encryptor/Decryptor")

frame = tk.Frame(root)
frame.pack(pady=20)

password1_label = tk.Label(frame, text="Mot de passe 1:")
password1_label.grid(row=0, column=0, padx=10)

password1_entry = tk.Entry(frame, show="*")
password1_entry.grid(row=0, column=1, padx=10)

password2_label = tk.Label(frame, text="Mot de passe 2:")
password2_label.grid(row=1, column=0, padx=10)

password2_entry = tk.Entry(frame, show="*")
password2_entry.grid(row=1, column=1, padx=10)

encrypt_file_button = tk.Button(frame, text="Chiffrer un fichier", command=select_file_encrypt)
encrypt_file_button.grid(row=2, column=0, pady=10)

decrypt_file_button = tk.Button(frame, text="Déchiffrer un fichier", command=select_file_decrypt)
decrypt_file_button.grid(row=2, column=1, pady=10)

encrypt_folder_button = tk.Button(frame, text="Chiffrer un dossier", command=select_folder_encrypt)
encrypt_folder_button.grid(row=3, column=0, pady=10)

decrypt_folder_button = tk.Button(frame, text="Déchiffrer un dossier", command=select_folder_decrypt)
decrypt_folder_button.grid(row=3, column=1, pady=10)

root.mainloop()


Étape 3 : Compilation en un exécutable
Utilisez PyInstaller pour compiler le script en un fichier .exe:

pyinstaller --onefile --windowed your_script_name.py

Cette commande va créer un exécutable dans le répertoire dist. L'option --onefile permet de créer un exécutable unique, et --windowed permet de supprimer la console qui s'affiche lors de l'exécution du programme.
