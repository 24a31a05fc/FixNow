"""Create the first private FixNow administrator account interactively."""
import getpass
import re
import sqlite3
from app.main import DB, hash_password, init_db


def main():
    init_db()
    email = input("Administrator email: ").strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise SystemExit("Enter a valid email address.")
    password = getpass.getpass("New admin password (minimum 12 characters): ")
    confirm = getpass.getpass("Confirm admin password: ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters.")
    if password != confirm:
        raise SystemExit("Passwords do not match.")
    con = sqlite3.connect(DB)
    try:
        existing = con.execute("SELECT id,role FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
        if existing:
            if existing[1] == "admin":
                raise SystemExit("An admin account with this email already exists; no changes made.")
            raise SystemExit("This email already belongs to a customer. Use a different private admin email.")
        con.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')", ("FixNow Administrator", email, hash_password(password)))
        con.commit()
        print("Administrator account created. Keep the password private and sign in using this email.")
    finally:
        con.close()


if __name__ == "__main__":
    main()
