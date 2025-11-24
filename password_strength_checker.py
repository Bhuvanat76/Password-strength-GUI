#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk
import string


class PasswordCheckerApp:
    def __init__(self, root):
        self.root = root
        root.title("Password Strength Checker")
        root.geometry("650x480")
        root.resizable(False, False)

        # ===== Main frame =====
        main_frame = ttk.Frame(root, padding=15)
        main_frame.pack(fill="both", expand=True)

        # ----- Title -----
        title_label = ttk.Label(
            main_frame,
            text="🔒 Password Strength Checker",
            font=("Segoe UI", 16, "bold")
        )
        title_label.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        # ----- Password input -----
        ttk.Label(main_frame, text="Enter password:", font=("Segoe UI", 11)).grid(
            row=1, column=0, sticky="w", pady=(0, 5)
        )

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            main_frame,
            textvariable=self.password_var,
            show="*",
            width=40,
            font=("Segoe UI", 11)
        )
        self.password_entry.grid(row=1, column=1, sticky="w", pady=(0, 5))

        # Show / Hide checkbox
        self.show_var = tk.BooleanVar(value=False)
        show_check = ttk.Checkbutton(
            main_frame,
            text="Show",
            variable=self.show_var,
            command=self.toggle_show
        )
        show_check.grid(row=1, column=2, sticky="w", padx=(5, 0))

        # ----- Strength bar -----
        ttk.Label(main_frame, text="Strength:", font=("Segoe UI", 11)).grid(
            row=2, column=0, sticky="w"
        )

        self.progress = ttk.Progressbar(
            main_frame,
            orient="horizontal",
            length=450,
            mode="determinate",
            maximum=10     # 10 criteria
        )
        self.progress.grid(row=2, column=1, columnspan=2, sticky="we", pady=(0, 5))

        # Strength text (Weak / Medium / Strong)
        self.strength_label = tk.Label(
            main_frame,
            text="",
            font=("Segoe UI", 11, "bold"),
            anchor="w"
        )
        self.strength_label.grid(row=3, column=0, columnspan=3, sticky="w", pady=(0, 10))

        # ----- Criteria frame -----
        criteria_frame = ttk.LabelFrame(main_frame, text="Criteria", padding=10)
        criteria_frame.grid(row=4, column=0, columnspan=3, sticky="nsew")

        main_frame.columnconfigure(1, weight=1)

        self.criteria_labels = {}
        # 10 criteria labels
        for key in [
            "length8", "length12", "upper", "lower", "digit",
            "special", "mixed_case", "letters_digits", "no_space", "not_common"
        ]:
            self.criteria_labels[key] = tk.Label(criteria_frame, anchor="w", font=("Segoe UI", 10))
            self.criteria_labels[key].pack(anchor="w")

        # Update strength on each key press
        self.password_entry.bind("<KeyRelease>", self.on_password_change)

        # Initial state (empty password)
        self.update_strength("")

    # ===== Logic functions =====
    def toggle_show(self):
        """Show/hide the password."""
        if self.show_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def analyze_password(self, password):
        """Check 10 criteria and compute score."""
        length = len(password)
        length8 = length >= 8
        length12 = length >= 12
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        mixed_case = has_upper and has_lower
        letters_digits = (any(c.isalpha() for c in password) and has_digit)
        no_space = not any(c.isspace() for c in password)

        # very small common list + pattern substrings
        common_list = {
            "password", "123456", "123456789", "qwerty",
            "admin", "letmein", "welcome", "abc123",
            "111111", "password1"
        }
        lower_pwd = password.lower()
        common_pattern = (
            lower_pwd in common_list or
            "password" in lower_pwd or
            "1234" in lower_pwd or
            "qwerty" in lower_pwd or
            "admin" in lower_pwd
        )
        not_common = (password != "" and not common_pattern)

        criteria_bools = [
            length8, length12, has_upper, has_lower, has_digit,
            has_special, mixed_case, letters_digits, no_space, not_common
        ]
        score = sum(criteria_bools)

        # Decide overall strength using score out of 10
        if score <= 3:
            strength = "Very Weak"
            color = "#d9534f"   # red
        elif 4 <= score <= 6:
            strength = "Weak"
            color = "#f0ad4e"   # orange
        elif 7 <= score <= 8:
            strength = "Medium"
            color = "#5bc0de"   # blue-ish
        elif 9 <= score <= 10:
            strength = "Strong"
            color = "#5cb85c"   # green
        else:
            strength = "Unknown"
            color = "black"

        return {
            "length8": length8,
            "length12": length12,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_special": has_special,
            "mixed_case": mixed_case,
            "letters_digits": letters_digits,
            "no_space": no_space,
            "not_common": not_common,
            "score": score,
            "strength": strength,
            "color": color,
        }

    def update_strength(self, password):
        """Update progress bar, strength text and criteria list."""
        result = self.analyze_password(password)

        # Progress bar
        self.progress["value"] = result["score"]

        # Strength text e.g. "Medium (score 7/10)"
        text = f"{result['strength']} (score {result['score']}/10)"
        self.strength_label.config(text=text, fg=result["color"])

        # Criteria lines
        self.set_criteria_label("length8", result["length8"], "Length ≥ 8")
        self.set_criteria_label("length12", result["length12"], "Length ≥ 12")
        self.set_criteria_label("upper", result["has_upper"], "Contains uppercase letter (A–Z)")
        self.set_criteria_label("lower", result["has_lower"], "Contains lowercase letter (a–z)")
        self.set_criteria_label("digit", result["has_digit"], "Contains number (0–9)")
        self.set_criteria_label("special", result["has_special"], "Contains special character (!@#...)")
        self.set_criteria_label("mixed_case", result["mixed_case"], "Has both upper and lower case")
        self.set_criteria_label("letters_digits", result["letters_digits"], "Has both letters and numbers")
        self.set_criteria_label("no_space", result["no_space"], "Contains no spaces")
        self.set_criteria_label("not_common", result["not_common"], "Not a common / guessable password")

    def set_criteria_label(self, key, ok, text):
        """Green ✔ when OK, red ✘ when not."""
        label = self.criteria_labels[key]
        if ok:
            label.config(text=f"\u2714 {text}", fg="#5cb85c")  # green check
        else:
            label.config(text=f"\u2718 {text}", fg="#d9534f")  # red cross

    def on_password_change(self, event):
        password = self.password_var.get()
        self.update_strength(password)


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCheckerApp(root)
    root.mainloop()
