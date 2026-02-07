import tkinter as tk
from tkinter import messagebox, scrolledtext
import hashlib
import random

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


# ---------------- GUI ---------------- #

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
        messagebox.showinfo("Copied", "Emoji copied to clipboard!")

def clear_convert():
    convert_input.delete("1.0", tk.END)
    convert_output.delete("1.0", tk.END)

def clear_resolve():
    resolve_input.delete("1.0", tk.END)
    resolve_output.delete("1.0", tk.END)


# ---------------- Main Window ---------------- #

root = tk.Tk()
root.title("🔥 EmojiCipher Pro 🔐")
root.geometry("850x650")
root.configure(bg="#111111")

title = tk.Label(root, text="EmojiCipher Pro",
                 font=("Helvetica", 26, "bold"),
                 fg="#00ffcc", bg="#111111")
title.pack(pady=15)

password_label = tk.Label(root, text="Secret Password",
                          fg="white", bg="#111111",
                          font=("Helvetica", 12, "bold"))
password_label.pack()

password_entry = tk.Entry(root, width=40, show="*",
                          font=("Helvetica", 12))
password_entry.pack(pady=5)


# -------- Convert Section -------- #

convert_frame = tk.LabelFrame(root, text=" Convert Message ",
                              fg="#00ffcc", bg="#1c1c1c",
                              font=("Helvetica", 12, "bold"),
                              padx=10, pady=10)
convert_frame.pack(padx=20, pady=15, fill="both")

convert_input = scrolledtext.ScrolledText(convert_frame,
                                          height=4,
                                          font=("Helvetica", 11))
convert_input.pack(pady=5)

convert_btn = tk.Button(convert_frame,
                        text="Convert 🔥",
                        command=convert_message,
                        bg="#00ffcc",
                        fg="black",
                        font=("Helvetica", 12, "bold"))
convert_btn.pack(pady=5)

convert_output = scrolledtext.ScrolledText(convert_frame,
                                           height=4,
                                           font=("Helvetica", 11))
convert_output.pack(pady=5)

button_frame1 = tk.Frame(convert_frame, bg="#1c1c1c")
button_frame1.pack()

copy_btn = tk.Button(button_frame1, text="Copy 📋",
                     command=copy_output,
                     bg="#ffaa00",
                     fg="black",
                     font=("Helvetica", 11, "bold"))
copy_btn.pack(side="left", padx=5)

clear_btn1 = tk.Button(button_frame1, text="Clear ❌",
                       command=clear_convert,
                       bg="#ff4444",
                       fg="white",
                       font=("Helvetica", 11, "bold"))
clear_btn1.pack(side="left", padx=5)


# -------- Resolve Section -------- #

resolve_frame = tk.LabelFrame(root, text=" Resolve Message ",
                              fg="#ff4081", bg="#1c1c1c",
                              font=("Helvetica", 12, "bold"),
                              padx=10, pady=10)
resolve_frame.pack(padx=20, pady=15, fill="both")

resolve_input = scrolledtext.ScrolledText(resolve_frame,
                                          height=4,
                                          font=("Helvetica", 11))
resolve_input.pack(pady=5)

resolve_btn = tk.Button(resolve_frame,
                        text="Resolve 🔓",
                        command=resolve_message,
                        bg="#ff4081",
                        fg="white",
                        font=("Helvetica", 12, "bold"))
resolve_btn.pack(pady=5)

resolve_output = scrolledtext.ScrolledText(resolve_frame,
                                           height=4,
                                           font=("Helvetica", 11))
resolve_output.pack(pady=5)

button_frame2 = tk.Frame(resolve_frame, bg="#1c1c1c")
button_frame2.pack()

clear_btn2 = tk.Button(button_frame2, text="Clear ❌",
                       command=clear_resolve,
                       bg="#ff4444",
                       fg="white",
                       font=("Helvetica", 11, "bold"))
clear_btn2.pack()

root.mainloop()
