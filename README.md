# PBKDF2 Hash Cracker

This tool cracks PBKDF2 hashes (commonly used by Flask/Werkzeug) by:
1. Parsing the hash format to extract algorithm, iterations, salt, and target hash
2. Reading passwords from a wordlist file (line by line, from start to end)
3. Hashing each password with the same salt and iterations
4. Comparing the computed hash with the target hash
5. Displaying the password when a match is found

## Requirements
```bash
Python 3.6+
```

## Usage
```bash
python3 hash_pbkdf2.py -w rockyou.txt -hash 'pbkdf2:sha256:<iterations>$<salt>$<hash_hex>'
```

## 📧 Contact
For questions or issues, please open a GitHub issue.
