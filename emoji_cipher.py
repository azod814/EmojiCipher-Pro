import tkinter as tk
from tkinter import messagebox, scrolledtext
import base64
import hashlib
import os
import random
from cryptography.fernet import Fernet

EMOJIS = [
"😀","😂","😎","😍","🤯","🥶","😈","🤖","👻","💀",
"🔥","⚡","🌊","🌪","🌙","☀","⭐","🌈","🍎","🍕",
"🚀","🛸","🎮","🎯","🧠","💎","🎵","🐶","🐱","🦊",
"🐼","🦁","🐍","🐢","🐙","🦋","🌻","🌴","🌍","🌎",
"🎲","🎰","🧩","📀","📱","💻","⌚","📡","🔐","🔑",
"❤️","💜","🖤","💛","💚","💙","🤍","🤎","💔","✨"
]

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="

def generate_key(password, salt):
    key = hashlib.sha256(password.encode() + salt).digest()
    return base64.urlsafe_b64encode(key)

def get_shuffled_emojis(password, salt):
    seed = int(hashlib.sha256(password.encode() + salt).hexdigest(), 16)
    random.seed(seed)
    shuffled = EMOJIS.copy()
    random.shuffle(shuffled)
    return shuffled

def encrypt_message(message, password):
    salt = os.urandom(8)
    key = generate_key(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(message.encode())
    b64 = base64.urlsafe_b64encode(encrypted).decode()

    shuffled = get_shuffled_emojis(password, salt)

    emoji_string = ""
    for char in b64:
        emoji_string += shuffled[BASE64_CHARS.index(char)]

    salt_b64 = base64.urlsafe_b64encode(salt).decode()
    salt_emojis = ""
    for char in salt_b64:
        salt_emojis += EMOJIS[BASE64_CHARS.index(char)]

    return salt_emojis + "|" + emoji_string

def decrypt_message(emoji_text, password):
    try:
        salt_part, emoji_part = emoji_text.split("|")

        salt_b64 = ""
        for e in salt_part:
            salt_b64 += BASE64_CHARS[EMOJIS.index(e)]
        salt = base64.urlsafe_b64decode(salt_b64)

        shuffled = get_shuffled_emojis(password, salt)

        encrypted_b64 = ""
        for e in emoji_part:
            encrypted_b64 += BASE64_CHARS[shuffled.index(e)]

        encrypted = base64.urlsafe_b64decode(encrypted_b64)

        key = generate_key(password, salt)
        f = Fernet(key)
        return f.decrypt(encrypted).decode()

    except:
        return None

def convert_message():
    msg = input_box.get("1.0", tk.END).strip()
    pwd = password_entry.get().strip()

    if not msg or not pwd:
        messagebox.showerror("Error", "Message and Password required!")
        return

    result = encrypt_message(msg, pwd)
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, result)

def resolve_message():
    msg = output_box.get("1.0", tk.END).strip()
    pwd = password_entry.get().strip()

    if not msg or not pwd:
        messagebox.showerror("Error", "Emoji text and Password required!")
        return

    result = decrypt_message(msg, pwd)

    if result:
        input_box.delete("1.0", tk.END)
        input_box.insert(tk.END, result)
    else:
        messagebox.showerror("Error", "Wrong password or corrupted emoji!")

root = tk.Tk()
root.title("EmojiCipher Pro 🔐")
root.geometry("700x550")
root.configure(bg="#1e1e1e")

title = tk.Label(root, text="EmojiCipher Pro", font=("Helvetica", 24, "bold"), fg="#00ffcc", bg="#1e1e1e")
title.pack(pady=10)

password_label = tk.Label(root, text="Secret Password:", fg="white", bg="#1e1e1e", font=("Helvetica", 12, "bold"))
password_label.pack()

password_entry = tk.Entry(root, width=40, show="*", font=("Helvetica", 12))
password_entry.pack(pady=5)

input_label = tk.Label(root, text="Enter Message:", fg="white", bg="#1e1e1e", font=("Helvetica", 12, "bold"))
input_label.pack()

input_box = scrolledtext.ScrolledText(root, height=5, width=70, font=("Helvetica", 11))
input_box.pack(pady=5)

convert_btn = tk.Button(root, text="Convert to Emoji 🔥", command=convert_message,
                        bg="#00ffcc", fg="black", font=("Helvetica", 12, "bold"))
convert_btn.pack(pady=10)

output_label = tk.Label(root, text="Emoji Output / Paste to Resolve:",
                        fg="white", bg="#1e1e1e", font=("Helvetica", 12, "bold"))
output_label.pack()

output_box = scrolledtext.ScrolledText(root, height=6, width=70, font=("Helvetica", 11))
output_box.pack(pady=5)

resolve_btn = tk.Button(root, text="Resolve Message 🔓", command=resolve_message,
                        bg="#ff4081", fg="white", font=("Helvetica", 12, "bold"))
resolve_btn.pack(pady=10)

root.mainloop()
