import tkinter as tk
from tkinter import messagebox
import re
import hashlib
import requests

def check_strength(password):
    score = 0
    suggestions = []

    # Length Score
    if len(password) >= 12:
        score += 40
    elif len(password) >= 8:
        score += 25
    else:
        score += 10
        suggestions.append("Use at least 12 characters")

    if re.search(r"[A-Z]", password):
        score += 10
    else:
        suggestions.append("Add uppercase letters")

    if re.search(r"[a-z]", password):
        score += 10
    else:
        suggestions.append("Add lowercase letters")

    if re.search(r"[0-9]", password):
        score += 10
    else:
        suggestions.append("Add numbers")

    if re.search(r"[@$!%*?&]", password):
        score += 10
    else:
        suggestions.append("Add special characters (@, #, %, *)")

    common_list = ["password", "123", "qwerty", "admin", "user"]
    if any(word in password.lower() for word in common_list):
        suggestions.append("Avoid common words or simple patterns")
        score -= 15

    strength = "Weak"
    if score >= 75:
        strength = "Strong"
    elif score >= 50:
        strength = "Medium"

    return score, strength, suggestions

def check_breach(password):
    sha1_pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5, tail = sha1_pass[:5], sha1_pass[5:]

    url = f"https://api.pwnedpasswords.com/range/{first5}"
    response = requests.get(url)

    if response.status_code != 200:
        return "API Error", 0

    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return "Found", int(count)

    return "Safe", 0

def analyze_password():
    password = entry.get()

    if not password:
        messagebox.showwarning("Warning", "Please enter a password!")
        return

   
    score, strength, suggestions = check_strength(password)

   
    if strength == "Weak":
        lbl_strength.config(fg="red")
    elif strength == "Medium":
        lbl_strength.config(fg="orange")
    else:
        lbl_strength.config(fg="green")

    lbl_strength.config(text=f"Strength: {strength} ({score}/100)")

    
    status, count = check_breach(password)
    if status == "Found":
        lbl_breach.config(text=f"⚠ Leaked {count} times!", fg="red")
    elif status == "Safe":
        lbl_breach.config(text="✔ No breach found!", fg="green")
    else:
        lbl_breach.config(text="API Error: Try again later", fg="orange")

   
    txt_suggestions.delete(0, tk.END)
    for s in suggestions:
        txt_suggestions.insert(tk.END, f"• {s}")



root = tk.Tk()
root.title("Password Security Analyzer")
root.geometry("430x450")
root.resizable(False, False)


tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=10)
entry = tk.Entry(root, show="*", font=("Arial", 14), width=30)
entry.pack()


tk.Button(root, text="Analyze", font=("Arial", 12, "bold"), command=analyze_password).pack(pady=10)

lbl_strength = tk.Label(root, text="Strength: ", font=("Arial", 14, "bold"))
lbl_strength.pack(pady=5)

lbl_breach = tk.Label(root, text="", font=("Arial", 12))
lbl_breach.pack(pady=5)


tk.Label(root, text="Suggestions:", font=("Arial", 12, "bold")).pack(pady=5)
txt_suggestions = tk.Listbox(root, width=45, height=8)
txt_suggestions.pack()

root.mainloop()
