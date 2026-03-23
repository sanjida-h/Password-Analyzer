from flask import Flask, render_template, request
from zxcvbn import zxcvbn
import hashlib
import requests
import secrets
import string
import random
import os

app = Flask(__name__)


def is_pwned(password):
    if not password:
        return 0
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5
        )
        for line in response.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)
    except:
        pass
    return 0


def generate_password(length, upper, lower, digits, symbols, memorable):
    if memorable:
        words = [
            "Purple",
            "Duck",
            "Potato",
            "Boat",
            "Sky",
            "Running",
            "Clear",
            "Fast",
            "Green",
            "Robot",
            "Apple",
            "Mountain",
            "Panda",
            "Wolf",
            "Chicken",
            "Monkey",
            "Home",
            "Work",
            "Burger",
            "Elephant",
            "Cow",
            "Rain",
            "Snow",
            "Sleep",
            "Cafe",
            "Train",
            "Pink",
            "River",
            "Cloud",
            "Stone",
            "Rat",
            "Light",
            "Shadow",
            "Fire",
            "Water",
            "Wind",
            "Tree",
            "Star",
            "Moon",
            "Dream",
            "Smile",
            "Coffee",
            "Bread",
            "Honey",
            "Music",
            "Velvet",
            "Orbit",
            "Lantern",
            "Echo",
            "Pixel",
            "Nova",
            "Drift",
            "Cipher",
            "Blaze",
            "Ivory",
            "Glacier",
            "Ember",
            "Horizon",
            "Mystic",
            "Vortex",
            "Comet",
            "Solace",
            "Breeze",
            "Cascade",
            "Aurora",
            "Rune",
            "Cosmic",
            "Lunar",
            "Solar",
            "Obsidian",
            "Marble",
            "Cobalt",
            "Crimson",
            "Saffron",
            "Indigo",
            "Topaz",
            "Onyx",
            "Jade",
            "Opal",
            "Silver",
            "Golden",
            "Velocity",
            "Drizzle",
            "Thunder",
            "Tempest",
            "Cyclone",
            "Monsoon",
            "Summit",
            "Valley",
            "Canyon",
            "Forest",
            "Harbor",
            "Desert",
            "Voyage",
            "Journey",
            "Quest",
            "Pathway",
            "Signal",
            "Beacon",
            "Matrix",
            "Circuit",
            "Vector",
            "Binary",
            "Kernel",
            "Protocol",
            "Nebula",
            "Galaxy",
            "Asteroid",
            "Eclipse",
            "Gravity",
            "Fusion",
            "Pulse",
            "Core",
            "Element",
            "Prime",
            "Momentum",
            "Spectrum",
        ]

        extras = ""
        if digits:
            extras += str(secrets.randbelow(10))
        if symbols:
            extras += secrets.choice("!@#$%^&*")
        # word build
        target_word_len = length - len(extras)
        chosen_words = []
        current_word_len = 0

        ##Separator logicccc
        sep = "-" if symbols else ""

        while current_word_len < target_word_len + 10:
            w = secrets.choice(words)

            # Strict casing logic
            if upper and not lower:
                w = w.upper()  # ALL CAPS
            elif upper:
                w = w.capitalize()  # First Letter Cap
            else:
                w = w.lower()  # all lowercase

            chosen_words.append(w)

            # recalculate length including separators
            current_word_len = sum(len(x) for x in chosen_words) + (
                len(chosen_words) - 1
            ) * len(sep)

        word_part = sep.join(chosen_words)

        # cut the word part to fit the exact length minus the extras
        final_password = word_part[:target_word_len] + extras
        return final_password

    # random string
    chars = ""
    if upper:
        chars += string.ascii_uppercase
    if lower:
        chars += string.ascii_lowercase
    if digits:
        chars += string.digits
    if symbols:
        chars += string.punctuation

    if not chars:
        return "Select Options!"

    return "".join(secrets.choice(chars) for _ in range(length))


def get_feedback(score, pwned, password):

    # Breach check
    if pwned > 0:
        return "DO NOT USE! This password has been found in a data breach."

    feedback_list = []

    # Actionable adice
    if len(password) < 12:
        feedback_list.append("Increase length (12+).")
    if not any(c.islower() for c in password):
        feedback_list.append("Add lowercase.")
    if not any(c.isupper() for c in password):
        feedback_list.append("Add uppercase.")
    if not any(c.isdigit() for c in password):
        feedback_list.append("Include numbers.")
    if not any(not c.isalnum() for c in password):
        feedback_list.append("Add symbols.")

    # feedback
    strength_messages = {
        0: [
            "This password provides negligible security and is highly vulnerable to automated attacks.",
            "The input is significantly below recommended complexity standards.",
            "This password does not meet basic data protection requirements.",
            "This password needs a lot of work",
        ],
        1: [
            "This password is quite simple and remains susceptible to common cracking methods.",
            "Adding a mix of character types is required to improve account security.",
            "This input offers very little resistance against brute-force attempts.",
        ],
        2: [
            "This is a functional password, but it does not meet modern security benchmarks.",
            "While acceptable for low-risk accounts, further complexity is recommended.",
            "This password provides baseline security but could be easily strengthened.",
        ],
        3: [
            "This is a secure password that follows most industry best practices.",
            "Your account is well-protected against standard unauthorised access attempts.",
            "This password provides a robust layer of protection for your data.",
        ],
        4: [
            "This password meets high security standard for data protection.",
            "You have achieved maximum entropy and robust resistance to attacks.",
            "This is an exceptionally strong password that provides top-tier security.",
        ],
    }

    # pick ONE random message from the correct score list
    summary_list = strength_messages.get(score, ["Analysis complete."])
    summary = random.choice(summary_list)

    # Output
    if not feedback_list:
        return summary

    # Combines the random summary with the specific fix suggestions
    return f"{summary} Suggested: {', '.join(feedback_list)}"


@app.route("/", methods=["GET", "POST"])
def index():
    password = request.form.get("password", "").replace(" ", "")
    action = request.form.get("action")
    show_password = request.form.get("show_password", "false")

    try:
        length = int(request.form.get("length", 12))
    except:
        length = 12

    upper = request.form.get("upper") or ("on" if request.method == "GET" else None)
    lower = request.form.get("lower") or ("on" if request.method == "GET" else None)
    digits = request.form.get("digits") or ("on" if request.method == "GET" else None)
    symbols = request.form.get("symbols") or ("on" if request.method == "GET" else None)
    memorable = request.form.get("memorable")

    if request.method == "POST":
        # Gets the current state of checkboxes for the "Auto" logic
        is_memorable = memorable == "on"

        # Auto generate follows the 'memorable' checkbox state
        # It forces all character types (True, True, True, True)
        # but respects the user's choice for word-based vs random
        if action == "auto":
            password = generate_password(length, True, True, True, True, is_memorable)

        # determine casing logic: if Upper is checked and lower is NOT, it will result in all caps

        elif action == "generate":

            password = generate_password(
                length,
                upper == "on",
                lower == "on",
                digits == "on",
                symbols == "on",
                memorable == "on",
            )

    analysis = None
    if password:
        res = zxcvbn(password)
        pwned_count = is_pwned(password)
        display_score = 0 if pwned_count > 0 else res["score"]
        analysis = {
            "score": display_score,
            "crack": res["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
            "pwned": pwned_count,
            "feedback": get_feedback(display_score, pwned_count, password),
            "label": ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"][
                display_score
            ],
            "length": len(password),
            "has_lower": any(c.islower() for c in password),
            "has_upper": any(c.isupper() for c in password),
            "has_digits": any(c.isdigit() for c in password),
            "has_symbols": any(not c.isalnum() for c in password),
        }

    return render_template(
        "index.html",
        password=password,
        analysis=analysis,
        show_password=show_password,
        length=length,
        upper=upper,
        lower=lower,
        digits=digits,
        symbols=symbols,
        memorable=memorable,
    )


# if __name__ == "__main__":
#     app.run(debug=True)
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
