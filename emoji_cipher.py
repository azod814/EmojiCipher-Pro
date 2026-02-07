import tkinter as tk
from tkinter import messagebox, scrolledtext
import hashlib
import random

# Large emoji pool (must be more than BASE_CHARS length)
EMOJIS = [
"😀","😂","😎","😍","🤯","🥶","😈","🤖","👻","💀",
"🔥","⚡","🌊","🌪","🌙","☀","⭐","🌈","🍎","🍕",
"🚀","🛸","🎮","🎯","🧠","💎","🎵","🐶","🐱","🦊",
"🐼","🦁","🐍","🐢","🐙","🦋","🌻","🌴","🌍","🌎",
"🎲","🎰","🧩","📀","📱","💻","⌚","📡","🔐","🔑",
"❤️","💜","🖤","💛","💚","💙","🤍","🤎","💔","✨",
"🥳","😇","🤠","👽","🧙","🦄","🐝","🐸","🐵","🐔",
"🐧","🐳","🐬","🐞","🌸","🍀","🍉","🍓","🍔","🥑"
]

BASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,!?@#"

# Generate deterministic seed
def generate_seed(password, salt):
    return int(hashlib.sha256((password + salt).encode()).hexdigest(), 16)

# Encrypt
def encrypt_message(message, password):
    salt = str(random.randint(1000, 9999))
    seed = generate_seed(password, salt)
    random.seed(seed)

    shuffled = EMOJIS.copy()
    random.shuffle(shuffled)

    emoji_string = ""
    for char in message:
        if char in BASE_CHARS:
            emoji_string += shuffled[BASE_CHARS.index(char)]
        else:
            emoji_string += char

    return salt + "|" + emoji_string

# Decrypt
def decrypt_message(emoji_text, password):
    try:
        salt, emoji_part = emoji_text.split("|")
        seed = generate_seed(password, salt)
        random.seed(seed)

        shuffled = EMOJIS.copy()
        random.shuffle(shuffled)

        original = ""
        for e in emoji_part:
            if e in shuffled:
                original += BASE_CHARS[shuffled.index(e)]
            else:
                original += e

        return original
    except:
        return None

# GUI Functions
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

    if result is not None:
        input_box.delete("1.0", tk.END)
        input_box.insert(tk.END, result)
    else:
        messagebox.showerror("Error", "Wrong password or corrupted emoji!")

# GUI Design
root = tk.Tk()
root.title("EmojiCipher Pro 🔐")
root.geometry("700x550")
root.configure(bg="#1e1e1e")

title = tk.Label(root, text="EmojiCipher Pro", font=("Helvetica", 24, "bold"),
                 fg="#00ffcc", bg="#1e1e1e")
title.pack(pady=10)

password_label = tk.Label(root, text="Secret Password:",
                          fg="white", bg="#1e1e1e",
                          font=("Helvetica", 12, "bold"))
password_label.pack()

password_entry = tk.Entry(root, width=40, show="*", font=("Helvetica", 12))
password_entry.pack(pady=5)

input_label = tk.Label(root, text="Enter Message:",
                       fg="white", bg="#1e1e1e",
                       font=("Helvetica", 12, "bold"))
input_label.pack()

input_box = scrolledtext.ScrolledText(root, height=5, width=70,
                                      font=("Helvetica", 11))
input_box.pack(pady=5)

convert_btn = tk.Button(root, text="Convert to Emoji 🔥",
                        command=convert_message,
                        bg="#00ffcc", fg="black",
                        font=("Helvetica", 12, "bold"))
convert_btn.pack(pady=10)

output_label = tk.Label(root,
                        text="Emoji Output / Paste to Resolve:",
                        fg="white", bg="#1e1e1e",
                        font=("Helvetica", 12, "bold"))
output_label.pack()

output_box = scrolledtext.ScrolledText(root, height=6, width=70,
                                       font=("Helvetica", 11))
output_box.pack(pady=5)

resolve_btn = tk.Button(root, text="Resolve Message 🔓",
                        command=resolve_message,
                        bg="#ff4081", fg="white",
                        font=("Helvetica", 12, "bold"))
resolve_btn.pack(pady=10)

root.mainloop()
