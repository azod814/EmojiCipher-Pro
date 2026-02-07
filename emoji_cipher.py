import tkinter as tk
from tkinter import messagebox, scrolledtext
import hashlib
import random

# Emoji Pool
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

def generate_seed(password, salt):
    return int(hashlib.sha256((password + salt).encode()).hexdigest(), 16)

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


# GUI FUNCTIONS

def convert_message():
    msg = convert_input.get("1.0", tk.END).strip()
    pwd = password_entry.get().strip()

    if not msg or not pwd:
        messagebox.showerror("Error", "Message & Password required!")
        return

    result = encrypt_message(msg, pwd)
    convert_output.delete("1.0", tk.END)
    convert_output.insert(tk.END, result)

def resolve_message():
    msg = resolve_input.get("1.0", tk.END).strip()
    pwd = password_entry.get().strip()

    if not msg or not pwd:
        messagebox.showerror("Error", "Emoji & Password required!")
        return

    result = decrypt_message(msg, pwd)

    if result:
        resolve_output.delete("1.0", tk.END)
        resolve_output.insert(tk.END, result)
    else:
        messagebox.showerror("Error", "Wrong password!")

def copy_output():
    text = convert_output.get("1.0", tk.END).strip()
    if text:
        root.clipboard_clear()
        root.clipboard_append(text)
        messagebox.showinfo("Copied", "Emoji copied!")

# MAIN WINDOW

root = tk.Tk()
root.title("🟢 EmojiCipher Pro - Hacker Edition")
root.geometry("1200x650")
root.configure(bg="#001a00")

title = tk.Label(root, text="EMOJICIPHER PRO",
                 font=("Courier", 28, "bold"),
                 fg="#00ff00", bg="#001a00")
title.pack(pady=15)

password_label = tk.Label(root, text="ENTER SECRET PASSWORD",
                          font=("Courier", 12, "bold"),
                          fg="#00ff00", bg="#001a00")
password_label.pack()

password_entry = tk.Entry(root, width=40, show="*",
                          font=("Courier", 12),
                          bg="#003300", fg="#00ff00",
                          insertbackground="#00ff00")
password_entry.pack(pady=5)


# MAIN FRAME (SIDE BY SIDE)
main_frame = tk.Frame(root, bg="#001a00")
main_frame.pack(fill="both", expand=True, padx=20, pady=20)


# LEFT - ENCRYPT
left_frame = tk.LabelFrame(main_frame,
                           text=" ENCRYPT MESSAGE ",
                           font=("Courier", 12, "bold"),
                           fg="#00ff00", bg="#002200",
                           padx=10, pady=10)
left_frame.pack(side="left", expand=True, fill="both", padx=10)

convert_input = scrolledtext.ScrolledText(left_frame,
                                          height=6,
                                          font=("Courier", 11),
                                          bg="#003300",
                                          fg="#00ff00",
                                          insertbackground="#00ff00")
convert_input.pack(pady=5)

convert_btn = tk.Button(left_frame,
                        text="ENCRYPT 🔐",
                        command=convert_message,
                        font=("Courier", 12, "bold"),
                        bg="#00aa00",
                        fg="black")
convert_btn.pack(pady=5)

convert_output = scrolledtext.ScrolledText(left_frame,
                                           height=6,
                                           font=("Courier", 11),
                                           bg="#003300",
                                           fg="#00ff00")
convert_output.pack(pady=5)

copy_btn = tk.Button(left_frame,
                     text="COPY 📋",
                     command=copy_output,
                     font=("Courier", 11, "bold"),
                     bg="#009900",
                     fg="black")
copy_btn.pack(pady=5)


# RIGHT - DECRYPT
right_frame = tk.LabelFrame(main_frame,
                            text=" DECRYPT MESSAGE ",
                            font=("Courier", 12, "bold"),
                            fg="#00ff00", bg="#002200",
                            padx=10, pady=10)
right_frame.pack(side="right", expand=True, fill="both", padx=10)

resolve_input = scrolledtext.ScrolledText(right_frame,
                                          height=6,
                                          font=("Courier", 11),
                                          bg="#003300",
                                          fg="#00ff00",
                                          insertbackground="#00ff00")
resolve_input.pack(pady=5)

resolve_btn = tk.Button(right_frame,
                        text="DECRYPT 🔓",
                        command=resolve_message,
                        font=("Courier", 12, "bold"),
                        bg="#00aa00",
                        fg="black")
resolve_btn.pack(pady=5)

resolve_output = scrolledtext.ScrolledText(right_frame,
                                           height=6,
                                           font=("Courier", 11),
                                           bg="#003300",
                                           fg="#00ff00")
resolve_output.pack(pady=5)

root.mainloop()
