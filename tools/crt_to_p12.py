#!/usr/bin/env python3
"""
Convert .crt + .key to PKCS12 (.p12) for Firefox - Robust version
"""

import sys
import getpass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import load_pem_x509_certificate


def create_pkcs12(cert_path: str, key_path: str, output_path: str = "browser.p12"):
    cert_path = Path(cert_path)
    key_path = Path(key_path)
    output_path = Path(output_path)

    if not cert_path.exists() or not key_path.exists():
        print("Error: One of the files was not found.")
        sys.exit(1)

    # Load certificate
    with open(cert_path, "rb") as f:
        cert = load_pem_x509_certificate(f.read())

    # Load private key - Smart handling
    with open(key_path, "rb") as f:
        key_data = f.read()

    print("Trying to load private key...")
    
    # First try: unencrypted key (most common for self-signed certs)
    try:
        private_key = serialization.load_pem_private_key(key_data, password=None)
        print("✓ Private key loaded successfully (unencrypted)")
    except serialization.UnsupportedAlgorithm:
        print("✗ Key uses unsupported algorithm")
        sys.exit(1)
    except Exception as e:
        # If it fails, ask for password
        print(f"Key appears to be encrypted: {e}")
        pwd = getpass.getpass("Enter private key password: ")
        private_key = serialization.load_pem_private_key(key_data, password=pwd.encode() if pwd else None)

    # === PKCS12 Password ===
    print("\nEnter a strong password to protect the .p12 file (required by Firefox):")
    while True:
        p12_pass = getpass.getpass()
        if len(p12_pass) < 4:
            print("Password should be at least 4 characters.")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if p12_pass == confirm:
            break
        print("Passwords do not match!")

    # Create PKCS12
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"Browser Self-Signed Cert",
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(p12_pass.encode())
    )

    output_path.write_bytes(p12_data)
    print(f"\n✅ Success! File created at:")
    print(f"   {output_path.resolve()}")
    print("\nImport it in Firefox:")
    print("Settings → Privacy & Security → Certificates → View Certificates → Import")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Create PKCS12 from crt + key")
    parser.add_argument("--cert", required=True, help="Path to .crt file")
    parser.add_argument("--key",  required=True, help="Path to .key file")
    parser.add_argument("--output", default="browser.p12", help="Output .p12 file")
    
    args = parser.parse_args()
    create_pkcs12(args.cert, args.key, args.output)

