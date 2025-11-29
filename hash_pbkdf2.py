#!/usr/bin/env python3
"""
PBKDF2 Hash Cracker
Attempts to crack PBKDF2-SHA256 hashes using a wordlist.
"""

import hashlib
import base64
import argparse
import sys
import time
from pathlib import Path
from typing import Optional

def parse_hash(hash_string: str) -> tuple:
    """
    Parse a PBKDF2 hash string into its components.
    
    Format: pbkdf2:sha256:iterations$salt_b64$hash_b64
    
    Returns:
        tuple: (algorithm, iterations, salt, expected_hash)
    """
    try:
        parts = hash_string.split('$')
        if len(parts) != 3:
            raise ValueError("Invalid hash format")
        
        header = parts[0]
        salt_b64 = parts[1]
        hash_b64 = parts[2]
        
        # Parse header (pbkdf2:sha256:iterations)
        header_parts = header.split(':')
        if len(header_parts) != 3 or header_parts[0] != 'pbkdf2':
            raise ValueError("Invalid hash format")
        
        algorithm = header_parts[1]
        iterations = int(header_parts[2])
        
        # Decode base64 values
        salt = base64.b64decode(salt_b64)
        expected_hash = base64.b64decode(hash_b64)
        
        return algorithm, iterations, salt, expected_hash
    
    except Exception as e:
        print(f"[!] Error parsing hash: {e}")
        sys.exit(1)

def hash_password(password: str, algorithm: str, iterations: int, salt: bytes) -> bytes:
    """
    Hash a password using PBKDF2.
    
    Args:
        password: Password to hash
        algorithm: Hash algorithm (e.g., 'sha256')
        iterations: Number of iterations
        salt: Salt bytes
        
    Returns:
        bytes: Derived key
    """
    return hashlib.pbkdf2_hmac(algorithm, password.encode(), salt, iterations)

def crack_hash(wordlist_path: str, target_hash: str, verbose: bool = False) -> Optional[str]:
    """
    Attempt to crack a PBKDF2 hash using a wordlist.
    
    Args:
        wordlist_path: Path to wordlist file
        target_hash: Target hash string to crack
        verbose: Print progress information
        
    Returns:
        str: Cracked password or None
    """
    # Parse the target hash
    algorithm, iterations, salt, expected_hash = parse_hash(target_hash)
    
    print(f"[*] Target Hash: {target_hash}")
    print(f"[*] Algorithm: PBKDF2-{algorithm.upper()}")
    print(f"[*] Iterations: {iterations:,}")
    print(f"[*] Salt: {base64.b64encode(salt).decode()}")
    print(f"[*] Expected Hash: {base64.b64encode(expected_hash).decode()}")
    print(f"[*] Loading wordlist: {wordlist_path}")
    print()
    
    # Check if wordlist exists
    wordlist_file = Path(wordlist_path)
    if not wordlist_file.exists():
        print(f"[!] Error: Wordlist file '{wordlist_path}' not found")
        sys.exit(1)
    
    # Count total lines for progress
    print("[*] Counting wordlist entries...", end='', flush=True)
    with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
        total_passwords = sum(1 for _ in f)
    print(f" {total_passwords:,} passwords found")
    print()
    
    # Performance estimation
    print("[*] Estimating performance...")
    test_password = "test"
    start_time = time.time()
    hash_password(test_password, algorithm, iterations, salt)
    time_per_hash = time.time() - start_time
    estimated_total_time = time_per_hash * total_passwords
    
    print(f"[*] Time per hash: ~{time_per_hash:.3f} seconds")
    print(f"[*] Estimated total time: ~{estimated_total_time/60:.1f} minutes ({estimated_total_time/3600:.1f} hours)")
    print(f"[*] Speed: ~{1/time_per_hash:.1f} passwords/second")
    print()
    print("[*] Starting attack...")
    print()
    
    # Try each password in wordlist
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            attempts = 0
            start_attack = time.time()
            last_update = start_attack
            
            for line in f:
                password = line.rstrip('\n\r')
                attempts += 1
                
                # Hash the password
                computed_hash = hash_password(password, algorithm, iterations, salt)
                
                # Check if it matches
                if computed_hash == expected_hash:
                    elapsed = time.time() - start_attack
                    print(f"\n[+] {'='*60}")
                    print(f"[+] PASSWORD FOUND!")
                    print(f"[+] {'='*60}")
                    print(f"[+] Password: {password}")
                    print(f"[+] Attempts: {attempts:,} / {total_passwords:,}")
                    print(f"[+] Time elapsed: {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")
                    print(f"[+] {'='*60}")
                    return password
                
                # Progress indicator every 10 passwords or every 5 seconds
                current_time = time.time()
                if attempts % 10 == 0 or (current_time - last_update) >= 5:
                    elapsed = current_time - start_attack
                    percent = (attempts / total_passwords) * 100
                    rate = attempts / elapsed if elapsed > 0 else 0
                    eta = (total_passwords - attempts) / rate if rate > 0 else 0
                    
                    print(f"[*] Progress: {attempts:,}/{total_passwords:,} ({percent:.2f}%) | "
                          f"Speed: {rate:.2f} p/s | "
                          f"Elapsed: {elapsed/60:.1f}m | "
                          f"ETA: {eta/60:.1f}m", 
                          end='\r', flush=True)
                    last_update = current_time
        
        elapsed = time.time() - start_attack
        print(f"\n\n[!] Password not found after {attempts:,} attempts")
        print(f"[!] Time elapsed: {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")
        return None
    
    except KeyboardInterrupt:
        elapsed = time.time() - start_attack
        print(f"\n\n[!] Interrupted by user after {attempts:,} attempts")
        print(f"[!] Time elapsed: {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error reading wordlist: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='PBKDF2 Hash Cracker - Crack PBKDF2-SHA256 hashes using a wordlist',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -w wordlist.txt -hash 'pbkdf2:sha256:600000$salt$hash'
  %(prog)s -w rockyou.txt -hash 'pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad...' -v
        '''
    )
    
    parser.add_argument('-w', '--wordlist',
                        required=True,
                        help='Path to wordlist file')
    
    parser.add_argument('-hash', '--hash',
                        required=True,
                        help='Target PBKDF2 hash (format: pbkdf2:algorithm:iterations$salt$hash)')
    
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='Verbose output (show progress)')
    
    args = parser.parse_args()
    
    # Start cracking
    print("[*] PBKDF2 Hash Cracker")
    print("[*] " + "=" * 50)
    print()
    
    result = crack_hash(args.wordlist, args.hash, args.verbose)
    
    if result:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()