"""
DecodeLabs Industrial Training Kit
Project 3: Phishing Awareness Analysis
-------------------------------------------------
Analyzes emails/messages for phishing indicators across 5 categories:
  1. Suspicious URLs
  2. Urgency / Pressure Keywords
  3. Credential Harvesting Requests
  4. Spoofed Sender Indicators
  5. Technical Red Flags

Returns:  Verdict (PHISHING / SUSPICIOUS / LIKELY SAFE),
          Confidence Score (0-100),
          Categorized Red Flags with explanations,
          Actionable Recommendations.

Includes 5 built-in sample emails for demonstration.
"""

import re


# ──────────────────────────────────────────────
# 1. DETECTION RULES (pattern → explanation)
# ──────────────────────────────────────────────

URGENCY_PHRASES = {
    "act now":                  "Creates artificial time pressure to bypass rational thinking.",
    "act immediately":          "Creates artificial time pressure to bypass rational thinking.",
    "immediate action":         "Creates artificial time pressure to bypass rational thinking.",
    "urgent":                   "Urgency language designed to prevent careful evaluation.",
    "verify your account":      "Legitimate services rarely ask you to 'verify' via email link.",
    "verify your identity":     "Legitimate services rarely ask you to 'verify' via email link.",
    "confirm your identity":    "Legitimate services rarely ask you to 'verify' via email link.",
    "suspended":                "Scare tactic — real providers send multiple notices, not one-shot threats.",
    "will be closed":           "Scare tactic — real providers send multiple notices, not one-shot threats.",
    "will be locked":           "Scare tactic — real providers send multiple notices, not one-shot threats.",
    "unauthorized activity":    "Designed to trigger fear so you click without thinking.",
    "unusual sign-in":          "Designed to trigger fear so you click without thinking.",
    "unauthorized access":      "Designed to trigger fear so you click without thinking.",
    "limited time":             "Artificial scarcity tactic common in phishing and scam emails.",
    "within 24 hours":          "Artificial deadline creates panic and discourages verification.",
    "within 48 hours":          "Artificial deadline creates panic and discourages verification.",
    "failure to comply":        "Threatening language meant to intimidate the reader into action.",
    "you have been selected":   "Classic lottery/prize scam opening line.",
    "congratulations":          "Often used in prize/lottery phishing scams.",
    "won a prize":              "Prize notification from unknown sources is almost always a scam.",
    "claim your reward":        "Bait phrase used to lure victims to malicious sites.",
    "risk of closure":          "Scare tactic to force hasty action.",
}

CREDENTIAL_PHRASES = {
    "enter your password":      "No legitimate service asks for your password via email.",
    "confirm your password":    "No legitimate service asks for your password via email.",
    "update your password":     "Legitimate password resets happen on official sites, not via email links.",
    "social security":          "SSN requests via email are always fraudulent.",
    "credit card number":       "Financial details should never be shared through email.",
    "bank account number":      "Financial details should never be shared through email.",
    "login credentials":        "Credential requests via email are a hallmark of phishing.",
    "enter your pin":           "PINs should only be entered on official, verified platforms.",
    "verification code":        "Attackers use this to hijack your two-factor authentication.",
    "one-time password":        "OTP interception is a common account takeover technique.",
    "wire transfer":            "Wire transfer requests via email are a major BEC (Business Email Compromise) indicator.",
    "send the funds":           "Fund transfer requests via email are a major fraud indicator.",
    "transfer the amount":      "Fund transfer requests via email are a major fraud indicator.",
    "date of birth":            "PII harvesting — date of birth is used for identity theft.",
}

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bl.ink", "short.io",
    "rb.gy", "cutt.ly", "shorturl.at",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".work", ".click",
    ".loan", ".racing", ".win", ".bid", ".stream",
    ".gq", ".cf", ".tk", ".ml", ".ga",
]

LOOKALIKE_DOMAINS = {
    "paypa1.com":     "paypal.com",
    "paypall.com":    "paypal.com",
    "pay-pal.com":    "paypal.com",
    "amaz0n.com":     "amazon.com",
    "amazom.com":     "amazon.com",
    "arnazon.com":    "amazon.com",
    "micr0soft.com":  "microsoft.com",
    "micosoft.com":   "microsoft.com",
    "g00gle.com":     "google.com",
    "gooogle.com":    "google.com",
    "app1e.com":      "apple.com",
    "appl3.com":      "apple.com",
    "netfliix.com":   "netflix.com",
    "nettflix.com":   "netflix.com",
    "faceb00k.com":   "facebook.com",
    "bankofarnerica.com": "bankofamerica.com",
    "wells-farg0.com":    "wellsfargo.com",
}

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".pif",
    ".vbs", ".js", ".wsf", ".msi", ".com",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear account holder",
    "dear valued customer", "dear sir/madam", "dear client",
    "dear member", "dear subscriber",
]


# ──────────────────────────────────────────────
# 2. ANALYSIS ENGINE
# ──────────────────────────────────────────────

def _extract_urls(text):
    """Pull all URLs from the message body."""
    return re.findall(r'https?://[^\s\]>"\']+', text, re.IGNORECASE)


def _extract_domain(url):
    """Get the domain portion from a URL."""
    match = re.search(r'https?://([^/\s?#]+)', url, re.IGNORECASE)
    return match.group(1).lower() if match else ""


def analyze_message(text, sender_email=""):
    """
    Main analysis function.

    Args:
        text:         The email/message body to analyze.
        sender_email: (Optional) The 'From' address for sender checks.

    Returns:
        dict with: verdict, score, red_flags[], recommendations[]
    """
    red_flags = []
    text_lower = text.lower()
    urls = _extract_urls(text)

    # ── Category 1: Suspicious URLs ──────────────────
    for url in urls:
        domain = _extract_domain(url)

        # IP-address link (e.g. http://192.168.1.1/login)
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            red_flags.append({
                "category": "Suspicious URL",
                "indicator": f"IP-address link: {url}",
                "explanation": "Legitimate organizations use domain names, not raw IP addresses. "
                               "IP links are used to evade domain-based security filters.",
            })

        # URL shortener
        for shortener in URL_SHORTENERS:
            if shortener in domain:
                red_flags.append({
                    "category": "Suspicious URL",
                    "indicator": f"URL shortener detected: {url}",
                    "explanation": f"The link uses '{shortener}' to hide the true destination. "
                                   "Attackers use URL shorteners to disguise malicious domains.",
                })
                break

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                red_flags.append({
                    "category": "Suspicious URL",
                    "indicator": f"Suspicious TLD '{tld}': {url}",
                    "explanation": f"The domain ends in '{tld}', a top-level domain commonly abused "
                                   "in phishing campaigns due to cheap/free registration.",
                })
                break

        # Lookalike domain
        for fake, real in LOOKALIKE_DOMAINS.items():
            if fake in domain:
                red_flags.append({
                    "category": "Spoofed Sender",
                    "indicator": f"Lookalike domain '{fake}' (impersonating {real}): {url}",
                    "explanation": f"The domain '{fake}' closely resembles '{real}' but is a "
                                   "typosquatting/homograph attack designed to trick you.",
                })
                break

        # '@' in URL (credential-stuffing trick)
        if "@" in url:
            red_flags.append({
                "category": "Suspicious URL",
                "indicator": f"'@' symbol in URL: {url}",
                "explanation": "The '@' in a URL makes the browser ignore everything before it, "
                               "letting attackers display a trusted domain while redirecting elsewhere.",
            })

        # Excessively long subdomain chain
        if domain.count(".") >= 4:
            red_flags.append({
                "category": "Suspicious URL",
                "indicator": f"Deep subdomain chain: {url}",
                "explanation": "Multiple subdomains (e.g. secure.login.bank.example.com) are used "
                               "to make a malicious URL appear legitimate at first glance.",
            })

        # Non-HTTPS
        if url.lower().startswith("http://"):
            red_flags.append({
                "category": "Suspicious URL",
                "indicator": f"Non-HTTPS link: {url}",
                "explanation": "The link uses unencrypted HTTP. Legitimate login/verification "
                               "pages always use HTTPS to protect data in transit.",
            })

    # ── Category 2: Urgency / Pressure ───────────────
    for phrase, explanation in URGENCY_PHRASES.items():
        if phrase in text_lower:
            # Find the line containing the phrase for context
            for line in text.split("\n"):
                if phrase in line.lower():
                    excerpt = line.strip()[:100]
                    break
            else:
                excerpt = phrase
            red_flags.append({
                "category": "Urgency / Pressure",
                "indicator": f"Phrase: \"{phrase}\"",
                "explanation": explanation,
                "excerpt": excerpt,
            })

    # ── Category 3: Credential Harvesting ────────────
    for phrase, explanation in CREDENTIAL_PHRASES.items():
        if phrase in text_lower:
            for line in text.split("\n"):
                if phrase in line.lower():
                    excerpt = line.strip()[:100]
                    break
            else:
                excerpt = phrase
            red_flags.append({
                "category": "Credential Harvesting",
                "indicator": f"Phrase: \"{phrase}\"",
                "explanation": explanation,
                "excerpt": excerpt,
            })

    # ── Category 4: Spoofed Sender ───────────────────
    if sender_email:
        sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""

        # Free email posing as corporate
        free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
        corporate_keywords = ["bank", "support", "helpdesk", "admin", "security",
                              "paypal", "amazon", "microsoft", "apple", "netflix"]

        if sender_domain in free_providers:
            sender_local = sender_email.split("@")[0].lower()
            for keyword in corporate_keywords:
                if keyword in sender_local:
                    red_flags.append({
                        "category": "Spoofed Sender",
                        "indicator": f"Corporate impersonation from free email: {sender_email}",
                        "explanation": f"The sender uses '{sender_domain}' (a free provider) but "
                                       f"the name contains '{keyword}', suggesting impersonation of a "
                                       "legitimate organization. Real companies use their own domains.",
                    })
                    break

    # ── Category 5: Technical Red Flags ──────────────
    # Generic greeting
    for greeting in GENERIC_GREETINGS:
        if greeting in text_lower:
            red_flags.append({
                "category": "Technical Red Flag",
                "indicator": f"Generic greeting: \"{greeting}\"",
                "explanation": "Legitimate organizations usually address you by name. "
                               "Generic greetings indicate a mass-sent phishing campaign.",
            })
            break  # Only flag once

    # Suspicious attachments mentioned
    for ext in SUSPICIOUS_EXTENSIONS:
        pattern = re.compile(r'\b\w+' + re.escape(ext) + r'\b', re.IGNORECASE)
        match = pattern.search(text)
        if match:
            red_flags.append({
                "category": "Technical Red Flag",
                "indicator": f"Suspicious attachment type: {match.group()}",
                "explanation": f"The file extension '{ext}' is commonly used to deliver malware. "
                               "Never open unexpected attachments with executable extensions.",
            })

    # Grammar / spelling indicators (simplified heuristic)
    grammar_indicators = [
        (r'\b(kindly|do the needful|revert back)\b',
         "Phrasing commonly associated with social-engineering scripts."),
        (r'[A-Z]{2,}\s+[A-Z]{2,}\s+[A-Z]{2,}',
         "Excessive capitalization is a common phishing tactic to convey urgency."),
    ]
    for pattern, explanation in grammar_indicators:
        if re.search(pattern, text, re.IGNORECASE if "IGNORECASE" not in pattern else 0):
            red_flags.append({
                "category": "Technical Red Flag",
                "indicator": "Suspicious language pattern detected",
                "explanation": explanation,
            })
            break  # Only flag once

    # ── SCORING & VERDICT ────────────────────────────
    # Weighted scoring: not all flags carry equal weight
    weight_map = {
        "Suspicious URL":       15,
        "Urgency / Pressure":   10,
        "Credential Harvesting": 20,
        "Spoofed Sender":       20,
        "Technical Red Flag":    8,
    }

    raw_score = 0
    for flag in red_flags:
        raw_score += weight_map.get(flag["category"], 5)

    # Clamp to 0-100
    confidence = min(raw_score, 100)

    if confidence >= 50:
        verdict = "PHISHING"
    elif confidence >= 20:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY SAFE"

    # ── RECOMMENDATIONS ──────────────────────────────
    recommendations = []
    if verdict == "PHISHING":
        recommendations = [
            "Do NOT click any links or download attachments in this message.",
            "Do NOT reply or provide any personal information.",
            "Report this email to your IT/security team immediately.",
            "Mark the sender as spam/phishing in your email client.",
            "If you already clicked a link, change your passwords immediately and enable 2FA.",
        ]
    elif verdict == "SUSPICIOUS":
        recommendations = [
            "Do not click any links until you verify the sender through an independent channel.",
            "Contact the supposed sender directly using a known, trusted phone number or website.",
            "Forward the message to your IT/security team for review.",
            "Check the sender's email address carefully for misspellings or free email domains.",
        ]
    else:
        recommendations = [
            "This message appears legitimate, but always remain vigilant.",
            "Verify links by hovering over them before clicking.",
            "When in doubt, contact the sender through an independent channel.",
        ]

    return {
        "verdict": verdict,
        "confidence": confidence,
        "red_flags": red_flags,
        "recommendations": recommendations,
        "stats": {
            "total_flags": len(red_flags),
            "urls_scanned": len(urls),
            "categories_triggered": list(set(f["category"] for f in red_flags)),
        }
    }


# ──────────────────────────────────────────────
# 3. BUILT-IN SAMPLE EMAILS
# ──────────────────────────────────────────────

SAMPLE_EMAILS = [
    {
        "name": "Sample 1: Fake Bank Verification",
        "sender": "security-alert@bankofarnerica.com",
        "subject": "URGENT: Your Account Has Been Suspended",
        "body": """Dear Customer,

We have detected unauthorized activity on your Bank of America account.
Your account has been temporarily suspended for your protection.

To restore access, you must verify your identity within 24 hours by
clicking the link below:

    http://bit.ly/3xR9kLm

Please confirm your password, date of birth, and the last four digits
of your Social Security number to complete the verification process.

Failure to comply will result in permanent account closure.

Thank you for your prompt attention.

Sincerely,
Bank of America Security Team
security-alert@bankofarnerica.com"""
    },
    {
        "name": "Sample 2: IT Support Password Reset",
        "sender": "helpdesk-support@gmail.com",
        "subject": "Password Reset Required - Action Needed",
        "body": """Dear User,

Our system has flagged an unusual sign-in attempt on your corporate account.
As a security measure, you are required to reset your password immediately.

Click here to reset your password:
    http://192.168.45.12/corporate-login/reset.php

Enter your login credentials on the page to proceed with the reset.
This link will expire in 48 hours.

If you did not request this, kindly ignore this email.

Best regards,
IT Support Team
helpdesk-support@gmail.com"""
    },
    {
        "name": "Sample 3: Prize / Lottery Scam",
        "sender": "winner-notification@prize-center.xyz",
        "subject": "Congratulations! You Have Been Selected!",
        "body": """CONGRATULATIONS!!!

You have been selected as the winner of our $1,000,000 International
Email Lottery Program! Your email address was chosen from a pool of
2.4 million entries worldwide.

To claim your reward, act immediately and provide the following:
  - Full Name
  - Date of Birth
  - Credit Card Number (for processing fee of $49.99)
  - Bank Account Number (for direct deposit)

Click here to claim your prize NOW:
    http://secure.login.verify.prize-center.xyz/claim

This is a limited time offer. Act now or forfeit your winnings!

Yours truly,
International Lottery Commission"""
    },
    {
        "name": "Sample 4: CEO / Boss Impersonation (BEC)",
        "sender": "ceo.johnson@gmail.com",
        "subject": "Urgent Wire Transfer Needed",
        "body": """Hi,

I need you to process an urgent wire transfer of $28,500 to our new
vendor before end of day. This is time-sensitive and I need it done
immediately.

Wire transfer details:
  Account: 4829-1038-5567
  Routing: 021000021
  Bank: First National, Cayman Islands

Please send the funds and confirm once done. Do not discuss this with
anyone else — it's confidential until the deal closes.

I'm in meetings all day so just handle this directly.

Thanks,
David Johnson, CEO

Sent from my iPhone"""
    },
    {
        "name": "Sample 5: Legitimate Email (Control)",
        "sender": "no-reply@github.com",
        "subject": "Your pull request #142 has been merged",
        "body": """Hi Angie,

Your pull request #142 "Fix null pointer in auth module" has been
successfully merged into the main branch by @teammate.

Changes:
  - Fixed null pointer exception in AuthService.java (line 87)
  - Added unit tests for edge case handling
  - Updated documentation in README.md

You can view the merged commit here:
    https://github.com/decodelabs/project-alpha/pull/142

Thanks for your contribution!

— GitHub Notifications
   Manage your notification settings:
   https://github.com/settings/notifications"""
    },
]


# ──────────────────────────────────────────────
# 4. CLI INTERFACE
# ──────────────────────────────────────────────

def print_report(result, sample=None):
    """Pretty-print an analysis report to the terminal."""
    divider = "=" * 60

    print(f"\n{divider}")
    if sample:
        print(f"  EMAIL: {sample['name']}")
        print(f"  From:  {sample['sender']}")
        print(f"  Subject: {sample['subject']}")
        print(f"{divider}")

    # Verdict
    icon = {"PHISHING": "🔴", "SUSPICIOUS": "🟡", "LIKELY SAFE": "🟢"}
    v = result["verdict"]
    print(f"\n  VERDICT:    {icon.get(v, '⚪')} {v}")
    print(f"  CONFIDENCE: {result['confidence']}%")
    print(f"  FLAGS FOUND: {result['stats']['total_flags']}")
    print(f"  URLs SCANNED: {result['stats']['urls_scanned']}")

    # Red flags
    if result["red_flags"]:
        print(f"\n{'─' * 60}")
        print("  RED FLAGS IDENTIFIED:")
        print(f"{'─' * 60}")
        for i, flag in enumerate(result["red_flags"], 1):
            print(f"\n  [{i}] [{flag['category']}]")
            print(f"      Indicator:   {flag['indicator']}")
            print(f"      Explanation: {flag['explanation']}")
            if "excerpt" in flag:
                print(f"      Context:     \"{flag['excerpt']}\"")

    # Recommendations
    print(f"\n{'─' * 60}")
    print("  RECOMMENDATIONS:")
    print(f"{'─' * 60}")
    for rec in result["recommendations"]:
        print(f"    → {rec}")

    print(f"\n{divider}\n")


def main():
    print("=" * 60)
    print("  DecodeLabs | Project 3: Phishing Awareness Analysis")
    print("=" * 60)

    while True:
        print("\nOptions:")
        print("  1-5  → Analyze a built-in sample email")
        for i, sample in enumerate(SAMPLE_EMAILS, 1):
            print(f"         {i}. {sample['name']}")
        print("    6  → Paste your own email/message to analyze")
        print("    q  → Quit")

        choice = input("\nEnter choice: ").strip().lower()

        if choice == "q":
            break
        elif choice in ("1", "2", "3", "4", "5"):
            sample = SAMPLE_EMAILS[int(choice) - 1]
            result = analyze_message(sample["body"], sample["sender"])
            print_report(result, sample)
        elif choice == "6":
            print("\nPaste your email/message below (type 'END' on a new line to finish):")
            lines = []
            while True:
                line = input()
                if line.strip().upper() == "END":
                    break
                lines.append(line)
            custom_text = "\n".join(lines)
            sender = input("Sender email (optional, press Enter to skip): ").strip()
            result = analyze_message(custom_text, sender)
            print_report(result)
        else:
            print("Invalid choice. Enter 1-5, 6, or q.")

    print("\nAnalysis session closed. Stay vigilant! 🛡️")


if __name__ == "__main__":
    main()
