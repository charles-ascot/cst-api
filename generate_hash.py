#!/usr/bin/env python3
"""
Run this once locally to generate your bcrypt password hash.
Paste the output into your Cloud Run ADMIN_PASSWORD_HASH environment variable.

Usage:
    python3 generate_hash.py
"""
import bcrypt
import getpass

password = getpass.getpass("Enter portal password: ")
confirm  = getpass.getpass("Confirm password: ")

if password != confirm:
    print("❌ Passwords do not match.")
    exit(1)

hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
print(f"\n✅ Password hash generated. Set this as ADMIN_PASSWORD_HASH in Cloud Run:\n\n{hashed}\n")
