#!/usr/bin/env python3
"""
PBKDF2 Hash Cracker
Attempts to crack PBKDF2-SHA256 hashes using a wordlist.
"""

import hashlib
import argparse
import sys
import time
from pathlib import Path
from typing import Optional

def parse_hash(hash_string: str) -> tuple:
    """
    Parse a PBKDF2 hash string into its components.
    
    Format: pbkdf2:sha256:iterations$salt$hash_hex
    
    Returns:
        tuple: (algorithm, iterations, salt_bytes, expected_hash_hex)
    """
    try:
        parts = hash_string.split('$')
        if len(parts) != 3:
            raise ValueError("Invalid hash format - expected 3 parts separated by $")
        
        header = parts[0]
        salt_str = parts[1]
        hash_hex = parts[2]
        
        # Parse header (pbkdf2:sha256:iterations)
        header_parts = header.split(':')
        if len(header_parts) != 3 or header_parts[0] != 'pbkdf2':
            raise ValueError("Invalid hash format - header should be pbkdf2:algorithm:iterations")
        
        algorithm = header_parts[1]
        iterations = int(header_parts[2])
        
        # Salt is used as raw bytes (ASCII encoded)
        salt = salt_str.encode('ascii')
        
        return algorithm, iterations, salt, hash_hex
    
    except Exception as e:
        print(f"[!] Error parsing hash: {e}")
        sys.exit(1)

def hash_password(password: str, algorithm: str, iterations: int, salt: bytes) -> str:
    """
    Hash a password using PBKDF2 and return hex string.
    
    Args:
        password: Password to hash
        algorithm: Hash algorithm (e.g., 'sha256')
        iterations: Number of iterations
        salt: Salt bytes
        
    Returns:
        str: Hash in hexadecimal format
    """
    dk = hashlib.pbkdf2_hmac(algorithm, password.encode(), salt, iterations, dklen=32)
    return dk.hex()

def crack_hash(wordlist_path: str, target_hash: str) -> Optional[str]:
    """
    Attempt to crack a PBKDF2 hash using a wordlist.
    
    Args:
        wordlist_path: Path to wordlist file
        target_hash: Target hash string to crack
        
    Returns:
        str: Cracked password or None
    """
    # Parse the target hash
    algorithm, iterations, salt, expected_hash_hex = parse_hash(target_hash)
    
    print(f"[*] Algorithm: PBKDF2-{algorithm.upper()}")
    print(f"[*] Iterations: {iterations:,}")
    print(f"[*] Salt: {salt.decode('ascii')}")
    print(f"[*] Expected hash: {expected_hash_hex}")
    print(f"[*] Wordlist: {wordlist_path}")
    print()
    
    # Check if wordlist exists
    wordlist_file = Path(wordlist_path)
    if not wordlist_file.exists():
        print(f"[!] Error: Wordlist file '{wordlist_path}' not found")
        sys.exit(1)
    
    # Count total lines
    print("[*] Counting passwords...", end='', flush=True)
    with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
        total_passwords = sum(1 for _ in f)
    print(f" {total_passwords:,} found")
    
    # Performance test
    print("[*] Testing speed...", end='', flush=True)
    start_time = time.time()
    hash_password("test", algorithm, iterations, salt)
    time_per_hash = time.time() - start_time
    
    print(f" ~{1/time_per_hash:.1f} passwords/sec")
    print(f"[*] Estimated time: ~{(time_per_hash * total_passwords)/60:.1f} min")
    print()
    print("[*] Starting attack from line 1 to end...")
    print()
    
    # Attack
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            attempts = 0
            start_attack = time.time()
            last_update = start_attack
            
            for line in f:
                password = line.rstrip('\n\r')
                if not password:  # Skip empty lines
                    continue
                    
                attempts += 1
                
                # Hash the password
                computed_hash_hex = hash_password(password, algorithm, iterations, salt)
                
                # Check if it matches
                if computed_hash_hex == expected_hash_hex:
                    elapsed = time.time() - start_attack
                    print(f"\n")
                    print(f"[+] ════════════════════════════════════════")
                    print(f"[+] PASSWORD FOUND!")
                    print(f"[+] ════════════════════════════════════════")
                    print(f"[+] Password: {password}")
                    print(f"[+] Position: Line {attempts}")
                    print(f"[+] Time: {elapsed:.1f} seconds")
                    print(f"[+] ════════════════════════════════════════")
                    return password
                
                # Progress update
                current_time = time.time()
                if attempts % 10 == 0 or (current_time - last_update) >= 5:
                    elapsed = current_time - start_attack
                    percent = (attempts / total_passwords) * 100
                    rate = attempts / elapsed if elapsed > 0 else 0
                    eta = (total_passwords - attempts) / rate if rate > 0 else 0
                    
                    print(f"[*] {attempts:,}/{total_passwords:,} ({percent:.2f}%) | "
                          f"{rate:.1f} p/s | "
                          f"Time: {elapsed/60:.1f}m | "
                          f"ETA: {eta/60:.1f}m", 
                          end='\r', flush=True)
                    last_update = current_time
        
        elapsed = time.time() - start_attack
        print(f"\n")
        print(f"[!] Password not found in wordlist")
        print(f"[!] Tried {attempts:,} passwords in {elapsed/60:.1f} minutes")
        return None
    
    except KeyboardInterrupt:
        elapsed = time.time() - start_attack
        print(f"\n")
        print(f"[!] Stopped by user after {attempts:,} attempts ({elapsed/60:.1f} min)")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='PBKDF2 Hash Cracker - Crack PBKDF2-SHA256 hashes using a wordlist',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Example:
  python3 hash_pbkdf2.py -w rockyou.txt -hash 'pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad...'
        '''
    )
    
    parser.add_argument('-w', '--wordlist',
                        required=True,
                        help='Path to wordlist file')
    
    parser.add_argument('-hash', '--hash',
                        required=True,
                        help='Target PBKDF2 hash (format: pbkdf2:algorithm:iterations$salt$hash)')
    
    args = parser.parse_args()
    
    result = crack_hash(args.wordlist, args.hash)
    
    if result:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()