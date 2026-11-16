"""
Password Strength Checker - Desktop GUI
PS No. 10 (extension)

A Tkinter application that scores password strength LIVE as you type -
no need to press Enter or a submit button. Reuses the exact same
rule-checking and complexity logic as password_strength_checker.py,
so the two never disagree.

Run with:  python password_strength_app.py
Requires:  Python 3 with tkinter (included in standard Python installs)
"""

import tkinter as tk
from tkinter import ttk

from password_strength_checker import (
    check_rules,
    calculate_score,
    classify_strength,
    calculate_complexity_score,
    get_suggestions,
    validate_input,
)

# Colors used for each strength level
STRENGTH_COLORS = {
    "Weak": "#e74c3c",      # red
    "Medium": "#f39c12",    # orange
    "Strong": "#27ae60",    # green
}


class PasswordStrengthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker")
        self.root.geometry("460x420")
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e2e")

        self._build_styles()
        self._build_widgets()

    # ---------- UI SETUP ----------

    def _build_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        for name, color in STRENGTH_COLORS.items():
            style.configure(
                f"{name}.Horizontal.TProgressbar",
                troughcolor="#2d2d44",
                background=color,
                bordercolor="#2d2d44",
                lightcolor=color,
                darkcolor=color,
            )
        style.configure(
            "Neutral.Horizontal.TProgressbar",
            troughcolor="#2d2d44",
            background="#555577",
            bordercolor="#2d2d44",
            lightcolor="#555577",
            darkcolor="#555577",
        )

    def _build_widgets(self):
        pad = {"padx": 20}

        title = tk.Label(
            self.root, text="Password Strength Checker",
            font=("Segoe UI", 16, "bold"), fg="white", bg="#1e1e2e"
        )
        title.pack(pady=(20, 5), **pad)

        subtitle = tk.Label(
            self.root, text="Type a password below - results update live",
            font=("Segoe UI", 9), fg="#aaaacc", bg="#1e1e2e"
        )
        subtitle.pack(pady=(0, 15), **pad)

        # --- Entry field + show/hide toggle ---
        entry_frame = tk.Frame(self.root, bg="#1e1e2e")
        entry_frame.pack(fill="x", **pad)

        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", self._on_password_change)

        self.entry = tk.Entry(
            entry_frame, textvariable=self.password_var, show="•",
            font=("Segoe UI", 13), bg="#2d2d44", fg="white",
            insertbackground="white", relief="flat", bd=8
        )
        self.entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.entry.focus()

        self.show_var = tk.BooleanVar(value=False)
        show_check = tk.Checkbutton(
            entry_frame, text="Show", variable=self.show_var,
            command=self._toggle_show, fg="white", bg="#1e1e2e",
            selectcolor="#2d2d44", activebackground="#1e1e2e",
            activeforeground="white", font=("Segoe UI", 9)
        )
        show_check.pack(side="left", padx=(10, 0))

        # --- Strength label ---
        self.strength_label = tk.Label(
            self.root, text="Strength: -", font=("Segoe UI", 13, "bold"),
            fg="#aaaacc", bg="#1e1e2e"
        )
        self.strength_label.pack(pady=(20, 5), **pad)

        self.strength_bar = ttk.Progressbar(
            self.root, style="Neutral.Horizontal.TProgressbar",
            length=420, maximum=5, value=0
        )
        self.strength_bar.pack(**pad)

        # --- Complexity label ---
        self.complexity_label = tk.Label(
            self.root, text="Complexity: -", font=("Segoe UI", 11),
            fg="#aaaacc", bg="#1e1e2e"
        )
        self.complexity_label.pack(pady=(15, 5), **pad)

        self.complexity_bar = ttk.Progressbar(
            self.root, style="Neutral.Horizontal.TProgressbar",
            length=420, maximum=10, value=0
        )
        self.complexity_bar.pack(**pad)

        # --- Suggestions ---
        self.suggestions_label = tk.Label(
            self.root, text="", font=("Segoe UI", 9), fg="#dddddd",
            bg="#1e1e2e", justify="left", anchor="w", wraplength=420
        )
        self.suggestions_label.pack(pady=(20, 0), fill="x", **pad)

    # ---------- EVENT HANDLERS ----------

    def _toggle_show(self):
        self.entry.config(show="" if self.show_var.get() else "•")

    def _on_password_change(self, *_args):
        password = self.password_var.get()

        is_valid, error = validate_input(password)
        if not is_valid:
            self._render_invalid(error)
            return

        rules = check_rules(password)
        score = calculate_score(rules)
        strength = classify_strength(score)
        complexity = calculate_complexity_score(password)
        suggestions = get_suggestions(rules)

        self._render_result(strength, score, complexity, suggestions)

    # ---------- RENDERING ----------

    def _render_invalid(self, message):
        self.strength_label.config(text=f"⚠ {message}", fg="#e74c3c")
        self.strength_bar.config(style="Neutral.Horizontal.TProgressbar", value=0)
        self.complexity_label.config(text="Complexity: -")
        self.complexity_bar.config(style="Neutral.Horizontal.TProgressbar", value=0)
        self.suggestions_label.config(text="")

    def _render_result(self, strength, score, complexity, suggestions):
        color = STRENGTH_COLORS[strength]

        self.strength_label.config(
            text=f"Strength: {strength}  ({score}/5)", fg=color
        )
        self.strength_bar.config(
            style=f"{strength}.Horizontal.TProgressbar", value=score
        )

        self.complexity_label.config(text=f"Complexity Score: {complexity}/10")
        # Color the complexity bar the same way the strength is colored,
        # since they track the same underlying password.
        self.complexity_bar.config(
            style=f"{strength}.Horizontal.TProgressbar", value=complexity
        )

        if suggestions:
            text = "Suggestions:\n• " + "\n• ".join(suggestions)
        else:
            text = "✓ No suggestions. Your password is secure."
        self.suggestions_label.config(text=text)


def main():
    root = tk.Tk()
    PasswordStrengthApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
