"""Generate an RSA signing keypair and an Argon2id admin password hash."""

import argparse
import getpass
from pathlib import Path

from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", default="secrets")
    args = parser.parse_args()
    destination = Path(args.directory).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    private_path = destination / "oauth-private.pem"
    public_path = destination / "oauth-public.pem"
    if private_path.exists() or public_path.exists():
        raise SystemExit("Refusing to overwrite an existing OAuth key")
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    password = getpass.getpass("Admin password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation or len(password) < 12:
        private_path.unlink(missing_ok=True)
        public_path.unlink(missing_ok=True)
        raise SystemExit("Passwords differ or contain fewer than 12 characters")
    print(f"ADMIN_PASSWORD_HASH='{PasswordHasher().hash(password)}'")
    print(f"OAUTH_SIGNING_KEY_PATH={private_path}")
    print(f"OAUTH_SIGNING_PUBLIC_KEY_PATH={public_path}")


if __name__ == "__main__":
    main()
