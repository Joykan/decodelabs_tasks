"""
DecodeLabs Industrial Training Kit
Project 3: Phishing Awareness Analysis - GUI Version
------------------------------------------------------
A Tkinter desktop app that lets the user:
  - Select from 5 built-in sample phishing emails
  - Paste custom email/message content for analysis
  - View color-coded verdict (PHISHING / SUSPICIOUS / LIKELY SAFE)
  - Browse categorized red flags with explanations
  - Copy the full analysis report to clipboard

Built on top of the analysis engine from phishing_analyzer.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

from phishing_analyzer import analyze_message, SAMPLE_EMAILS


# ── Color Palette (matching DecodeLabs style) ────
BG           = "#eef0f5"
CARD_BG      = "#ffffff"
ACCENT       = "#5a6d8a"
ACCENT_DARK  = "#3d4f6b"
TEXT_PRIMARY  = "#2c2c2c"
TEXT_SECONDARY = "#6b7280"
RED           = "#dc3545"
RED_BG        = "#fde8ea"
YELLOW        = "#f0ad4e"
YELLOW_BG     = "#fff8e1"
GREEN         = "#28a745"
GREEN_BG      = "#e6f9ed"
DIVIDER       = "#d1d5db"


class PhishingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DecodeLabs - Project 3: Phishing Awareness Analysis")
        self.root.geometry("780x820")
        self.root.configure(bg=BG)
        self.root.minsize(700, 750)

        # ── Title ─────────────────────────────────
        title_frame = tk.Frame(root, bg=ACCENT_DARK, pady=12)
        title_frame.pack(fill="x")

        tk.Label(
            title_frame,
            text="🛡️  Phishing Awareness Analysis",
            font=("Segoe UI", 17, "bold"),
            bg=ACCENT_DARK, fg="white",
        ).pack()

        tk.Label(
            title_frame,
            text="DecodeLabs  •  Project 3  •  Threat Identification",
            font=("Segoe UI", 9),
            bg=ACCENT_DARK, fg="#b0bec5",
        ).pack()

        # ── Main container with scrollbar ─────────
        container = tk.Frame(root, bg=BG)
        container.pack(fill="both", expand=True, padx=16, pady=10)

        # ── Sample Selector ───────────────────────
        selector_frame = tk.LabelFrame(
            container, text=" Load Sample Email ",
            font=("Segoe UI", 10, "bold"),
            bg=CARD_BG, fg=ACCENT_DARK,
            relief="groove", bd=1, padx=10, pady=8,
        )
        selector_frame.pack(fill="x", pady=(0, 8))

        sample_names = [s["name"] for s in SAMPLE_EMAILS]
        self.sample_var = tk.StringVar(value=sample_names[0])

        combo_row = tk.Frame(selector_frame, bg=CARD_BG)
        combo_row.pack(fill="x")

        self.sample_combo = ttk.Combobox(
            combo_row, textvariable=self.sample_var,
            values=sample_names, state="readonly", width=50,
            font=("Segoe UI", 9),
        )
        self.sample_combo.pack(side="left", padx=(0, 10))

        tk.Button(
            combo_row, text="Load Sample", width=14,
            bg=ACCENT, fg="white", font=("Segoe UI", 9, "bold"),
            activebackground=ACCENT_DARK, activeforeground="white",
            relief="flat", cursor="hand2",
            command=self.load_sample,
        ).pack(side="left")

        # ── Sender field ──────────────────────────
        sender_frame = tk.Frame(container, bg=BG)
        sender_frame.pack(fill="x", pady=(0, 4))

        tk.Label(
            sender_frame, text="Sender Email (optional):",
            font=("Segoe UI", 9), bg=BG, fg=TEXT_SECONDARY,
        ).pack(side="left")

        self.sender_entry = tk.Entry(
            sender_frame, width=45,
            font=("Segoe UI", 9), relief="solid", bd=1,
        )
        self.sender_entry.pack(side="left", padx=(8, 0))

        # ── Input Text Area ──────────────────────
        tk.Label(
            container, text="Email / Message Content:",
            font=("Segoe UI", 10, "bold"), bg=BG, fg=ACCENT_DARK, anchor="w",
        ).pack(fill="x", pady=(8, 2))

        self.input_text = scrolledtext.ScrolledText(
            container, height=10, wrap="word",
            font=("Consolas", 9), relief="solid", bd=1,
            bg="#fafbfc",
        )
        self.input_text.pack(fill="x", pady=(0, 8))

        # ── Action Buttons ────────────────────────
        button_frame = tk.Frame(container, bg=BG)
        button_frame.pack(fill="x", pady=(0, 8))

        tk.Button(
            button_frame, text="🔍  Analyze Message", width=20,
            bg="#c0392b", fg="white", font=("Segoe UI", 11, "bold"),
            activebackground="#a93226", activeforeground="white",
            relief="flat", cursor="hand2", pady=4,
            command=self.run_analysis,
        ).pack(side="left", padx=(0, 10))

        tk.Button(
            button_frame, text="Clear", width=10,
            bg="#bdc3c7", fg=TEXT_PRIMARY, font=("Segoe UI", 9),
            relief="flat", cursor="hand2",
            command=self.clear_all,
        ).pack(side="left", padx=(0, 10))

        tk.Button(
            button_frame, text="📋 Copy Report", width=12,
            bg=ACCENT, fg="white", font=("Segoe UI", 9),
            relief="flat", cursor="hand2",
            command=self.copy_report,
        ).pack(side="left")

        # ── Verdict Banner ────────────────────────
        self.verdict_frame = tk.Frame(container, bg=BG, pady=6)
        self.verdict_frame.pack(fill="x")

        self.verdict_label = tk.Label(
            self.verdict_frame, text="",
            font=("Segoe UI", 14, "bold"), bg=BG,
        )
        self.verdict_label.pack()

        self.stats_label = tk.Label(
            self.verdict_frame, text="",
            font=("Segoe UI", 9), bg=BG, fg=TEXT_SECONDARY,
        )
        self.stats_label.pack()

        # ── Results Area ──────────────────────────
        self.results_text = scrolledtext.ScrolledText(
            container, height=16, wrap="word",
            font=("Consolas", 9), relief="solid", bd=1,
            bg="#fafbfc", state="disabled",
        )
        self.results_text.pack(fill="both", expand=True)

        # Configure text tags for color-coded output
        self.results_text.tag_config("header",   font=("Segoe UI", 10, "bold"), foreground=ACCENT_DARK)
        self.results_text.tag_config("flag_num", font=("Consolas", 9, "bold"),  foreground=RED)
        self.results_text.tag_config("category", font=("Consolas", 9, "bold"),  foreground="#8e44ad")
        self.results_text.tag_config("explain",  font=("Consolas", 9),          foreground=TEXT_SECONDARY)
        self.results_text.tag_config("rec",      font=("Consolas", 9),          foreground="#2980b9")
        self.results_text.tag_config("safe",     font=("Consolas", 9),          foreground=GREEN)

        # Store last report for copy
        self._last_report = ""

    # ── Load a sample email into the input fields ──
    def load_sample(self):
        selected = self.sample_var.get()
        for sample in SAMPLE_EMAILS:
            if sample["name"] == selected:
                self.input_text.delete("1.0", tk.END)
                self.input_text.insert("1.0", sample["body"])
                self.sender_entry.delete(0, tk.END)
                self.sender_entry.insert(0, sample["sender"])
                break

    # ── Run the analysis engine ────────────────────
    def run_analysis(self):
        text = self.input_text.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Empty Input", "Please enter or load an email/message to analyze.")
            return

        sender = self.sender_entry.get().strip()
        result = analyze_message(text, sender)

        # Update verdict banner
        v = result["verdict"]
        conf = result["confidence"]

        if v == "PHISHING":
            self.verdict_label.config(text=f"🔴  VERDICT: {v}  ({conf}% confidence)", fg=RED)
            self.verdict_frame.config(bg=RED_BG)
            self.verdict_label.config(bg=RED_BG)
            self.stats_label.config(bg=RED_BG)
        elif v == "SUSPICIOUS":
            self.verdict_label.config(text=f"🟡  VERDICT: {v}  ({conf}% confidence)", fg="#e67e22")
            self.verdict_frame.config(bg=YELLOW_BG)
            self.verdict_label.config(bg=YELLOW_BG)
            self.stats_label.config(bg=YELLOW_BG)
        else:
            self.verdict_label.config(text=f"🟢  VERDICT: {v}  ({conf}% confidence)", fg=GREEN)
            self.verdict_frame.config(bg=GREEN_BG)
            self.verdict_label.config(bg=GREEN_BG)
            self.stats_label.config(bg=GREEN_BG)

        stats = result["stats"]
        self.stats_label.config(
            text=f"{stats['total_flags']} red flag(s)  •  {stats['urls_scanned']} URL(s) scanned  •  "
                 f"Categories: {', '.join(stats['categories_triggered']) if stats['categories_triggered'] else 'None'}",
            fg=TEXT_SECONDARY,
        )

        # Build results text
        self.results_text.config(state="normal")
        self.results_text.delete("1.0", tk.END)

        report_lines = []

        if result["red_flags"]:
            self.results_text.insert(tk.END, "RED FLAGS IDENTIFIED:\n", "header")
            self.results_text.insert(tk.END, "─" * 56 + "\n\n")
            report_lines.append("RED FLAGS IDENTIFIED:")
            report_lines.append("─" * 56)

            for i, flag in enumerate(result["red_flags"], 1):
                line1 = f"[{i}] "
                line2 = f"[{flag['category']}]\n"
                self.results_text.insert(tk.END, line1, "flag_num")
                self.results_text.insert(tk.END, line2, "category")

                ind_line = f"    Indicator:   {flag['indicator']}\n"
                exp_line = f"    Explanation: {flag['explanation']}\n"
                self.results_text.insert(tk.END, ind_line)
                self.results_text.insert(tk.END, exp_line, "explain")

                report_lines.append(f"[{i}] [{flag['category']}]")
                report_lines.append(f"    Indicator:   {flag['indicator']}")
                report_lines.append(f"    Explanation: {flag['explanation']}")

                if "excerpt" in flag:
                    ctx_line = f"    Context:     \"{flag['excerpt']}\"\n"
                    self.results_text.insert(tk.END, ctx_line, "explain")
                    report_lines.append(f"    Context:     \"{flag['excerpt']}\"")

                self.results_text.insert(tk.END, "\n")
                report_lines.append("")
        else:
            self.results_text.insert(tk.END, "No red flags detected.\n\n", "safe")
            report_lines.append("No red flags detected.")
            report_lines.append("")

        self.results_text.insert(tk.END, "RECOMMENDATIONS:\n", "header")
        self.results_text.insert(tk.END, "─" * 56 + "\n\n")
        report_lines.append("RECOMMENDATIONS:")
        report_lines.append("─" * 56)

        for rec in result["recommendations"]:
            rec_line = f"  → {rec}\n"
            self.results_text.insert(tk.END, rec_line, "rec")
            report_lines.append(f"  → {rec}")

        self.results_text.config(state="disabled")

        # Store full report for copying
        header = f"VERDICT: {v} ({conf}% confidence)\n"
        header += f"Flags: {stats['total_flags']} | URLs scanned: {stats['urls_scanned']}\n\n"
        self._last_report = header + "\n".join(report_lines)

    # ── Clear all fields ───────────────────────────
    def clear_all(self):
        self.input_text.delete("1.0", tk.END)
        self.sender_entry.delete(0, tk.END)
        self.verdict_label.config(text="", bg=BG)
        self.stats_label.config(text="", bg=BG)
        self.verdict_frame.config(bg=BG)
        self.results_text.config(state="normal")
        self.results_text.delete("1.0", tk.END)
        self.results_text.config(state="disabled")
        self._last_report = ""

    # ── Copy report to clipboard ───────────────────
    def copy_report(self):
        if not self._last_report:
            messagebox.showinfo("No Report", "Run an analysis first to generate a report.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self._last_report)
        messagebox.showinfo("Copied", "Analysis report copied to clipboard!")


if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingApp(root)
    root.mainloop()
