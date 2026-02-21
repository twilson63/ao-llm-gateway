"""Utility script for admin password and key management."""
import argparse
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.encryption import hash_password, verify_password, generate_encryption_key
from src.auth.jwt_handler import create_access_token


def main():
    parser = argparse.ArgumentParser(description="AO LLM Gateway Admin Utilities")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Password hash command
    hash_parser = subparsers.add_parser("hash-password", help="Generate bcrypt hash for password")
    hash_parser.add_argument("password", help="Password to hash")
    
    # Verify password command
    verify_parser = subparsers.add_parser("verify-password", help="Verify password against hash")
    verify_parser.add_argument("password", help="Password to verify")
    verify_parser.add_argument("hash", help="Hash to verify against")
    
    # Generate encryption key
    key_parser = subparsers.add_parser("generate-key", help="Generate Fernet encryption key")
    
    # Generate JWT token
    token_parser = subparsers.add_parser("create-token", help="Create JWT token for testing")
    token_parser.add_argument("--email", default="admin@example.com", help="Email for token")
    token_parser.add_argument("--role", default="admin", help="Role for token")
    token_parser.add_argument("--minutes", type=int, default=30, help="Token expiration in minutes")
    
    args = parser.parse_args()
    
    if args.command == "hash-password":
        hashed = hash_password(args.password)
        print(f"Password hash: {hashed}")
        print(f"\nAdd to .env:")
        print(f"ADMIN_PASSWORD={hashed}")
        
    elif args.command == "verify-password":
        result = verify_password(args.password, args.hash)
        if result:
            print("✓ Password is valid")
        else:
            print("✗ Password is invalid")
            
    elif args.command == "generate-key":
        key = generate_encryption_key()
        print(f"Encryption key: {key}")
        print(f"\nAdd to .env:")
        print(f"ENCRYPTION_KEY={key}")
        
    elif args.command == "create-token":
        from datetime import timedelta
        token = create_access_token(
            {"sub": {"email": args.email, "role": args.role}},
            expires_delta=timedelta(minutes=args.minutes)
        )
        print(f"JWT Token:\n{token}")
        
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
