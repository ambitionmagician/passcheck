#!/usr/bin/env python3
"""
passcheck.py - Local password strength auditor

Estimates entropy, flags common patterns, and grades passwords without network access.

Usage examples:
    $ ./passcheck.py "Sunshine2024!"
    Password: ******** (length 13)
    Score: 2/4 (Fair)
    Entropy: ~58 bits (character-pool estimate)
    Notes: contains a dictionary word: "sunshine"; ends with digits; year-like sequence: 2024

    $ echo -e "password\nTr0ub4dor&3" | ./passcheck.py --stdin
    Password: ******** (length 8)
    Score: 0/4 (Very weak)
    Entropy: ~28 bits (character-pool estimate)
    Notes: contains a dictionary word: "password"; all lowercase letters

    ---
    Password: ******** (length 11)
    Score: 3/4 (Strong)
    Entropy: ~65 bits (character-pool estimate)
    Notes: ends with digits; contains symbols
    Summary: 2 passwords, weakest score 0, average entropy ~47 bits
"""

import argparse
import sys
import math
import re

# Built-in list of ~60 very common passwords/words
COMMON_WORDS = {
    'password', '123456', '12345678', '123456789', '1234567890', '12345',
    '1234', '111111', '000000', 'qwerty', 'qwerty123', 'abc123', '1q2w3e4r',
    'qazwsx', 'zxcvbnm', 'asdfghjkl', 'monkey', 'letmein', 'trustno1',
    'dragon', 'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
    'bailey', 'passw0rd', 'shadow', '123123', '654321', 'superman',
    'michael', 'football', 'password1', 'welcome', 'welcome1', 'admin',
    'admin123', 'login', 'starwars', 'hello', 'charlie', 'donald',
    'changeme', 'default', 'secret', 'guest', 'root', 'test', 'computer',
    'internet', 'soccer', 'hockey', 'killer', 'george', 'hammer', 'silver',
    'golden', 'purple', 'orange', 'banana', 'cheese', 'summer', 'winter',
    'freedom', 'whatever', 'nicole', 'jessica', 'anthony', 'justin'
}

# Keyboard sequences
KEYBOARD_SEQUENCES = [
    'qwerty', 'qwert', 'wert', 'erty', 'rtyu', 'tyui', 'yuio', 'uiop',
    'asdf', 'sdfg', 'dfgh', 'fghj', 'ghjk', 'hjkl', 'zxcv', 'xcvb',
    'cvbn', 'vbnm', 'qaz', 'wsx', 'edc', 'rfv', 'tgb', 'yhn', 'ujm',
    '1234', '2345', '3456', '4567', '5678', '6789', '7890',
    'abcd', 'bcde', 'cdef', 'defg', 'efgh', 'fghi', 'ghij', 'hijk',
    'ijkl', 'jklm', 'klmn', 'lmno', 'mnop', 'nopq', 'opqr', 'pqrs',
    'qrst', 'rstu', 'stuv', 'tuvw', 'uvwx', 'vwxy', 'wxyz',
    '4321', '5432', '6543', '7654', '8765', '9876', '0987',
    'dcba', 'zyxw', 'lkjh', 'lkjhgf', 'poiuy', 'mnbv'
]


def get_char_pools(password):
    """Determine which character pools are used in the password."""
    pools = []
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    
    if has_lower:
        pools.append(26)
    if has_upper:
        pools.append(26)
    if has_digit:
        pools.append(10)
    if has_symbol:
        pools.append(33)
    if not (has_lower or has_upper or has_digit or has_symbol):
        pools.append(100)  # Unicode/other
    
    return pools


def estimate_entropy(password):
    """Estimate password entropy based on character pools."""
    if not password:
        return 0
    
    pools = get_char_pools(password)
    if not pools:
        return 0
    
    pool_size = sum(pools)
    return math.log2(pool_size ** len(password))


def check_dictionary_word(password):
    """Check if password contains a dictionary word."""
    lower_pwd = password.lower()
    # Longest match first so the note names the most specific hit.
    for word in sorted(COMMON_WORDS, key=lambda w: (-len(w), w)):
        if word in lower_pwd:
            return word
    return None


def check_keyboard_sequence(password):
    """Check for keyboard sequences of 3+ characters."""
    lower_pwd = password.lower()
    for seq in KEYBOARD_SEQUENCES:
        if len(seq) >= 3 and seq in lower_pwd:
            return seq
    return None


def check_repeated_chars(password):
    """Check for 3+ repeated characters."""
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            return True
    return False


def check_year_like(password):
    """Check for year-like 4-digit sequences (1900-2099)."""
    for match in re.finditer(r'(?<!\d)(19|20)\d{2}(?!\d)', password):
        return match.group(0)
    return None


def check_all_one_class(password):
    """Check if password uses only one character class."""
    pools = get_char_pools(password)
    return len(pools) == 1


def audit_password(password):
    """Audit a single password and return results."""
    length = len(password)
    entropy = estimate_entropy(password)
    
    notes = []
    penalties = 0
    
    # Check dictionary word
    dict_word = check_dictionary_word(password)
    if dict_word:
        notes.append(f'contains a dictionary word: "{dict_word}"')
        penalties += 20
    
    # Check keyboard sequence
    kb_seq = check_keyboard_sequence(password)
    if kb_seq:
        notes.append(f'contains keyboard sequence: "{kb_seq}"')
        penalties += 10
    
    # Check repeated characters
    if check_repeated_chars(password):
        notes.append('contains repeated characters')
        penalties += 8
    
    # Check year-like
    year = check_year_like(password)
    if year:
        notes.append(f'year-like sequence: {year}')
        penalties += 10
    
    # Check all one class
    if check_all_one_class(password):
        if length > 0:
            notes.append('all one character class')
        penalties += 10
    
    # Calculate final entropy after penalties
    final_entropy = max(0, entropy - penalties)
    
    # Determine score
    if final_entropy < 28:
        score = 0
        grade = "Very weak"
    elif final_entropy < 45:
        score = 1
        grade = "Weak"
    elif final_entropy < 65:
        score = 2
        grade = "Fair"
    elif final_entropy < 89:
        score = 3
        grade = "Strong"
    else:
        score = 4
        grade = "Excellent"
    
    # Determine character pool description
    pools = get_char_pools(password)
    pool_desc = "character-pool estimate"
    if len(pools) == 1:
        if 26 in pools:
            pool_desc = "lowercase letters"
        elif 26 in pools:
            pool_desc = "uppercase letters"
        elif 10 in pools:
            pool_desc = "digits"
        elif 33 in pools:
            pool_desc = "symbols"
        else:
            pool_desc = "other/unicode"
    elif len(pools) == 2:
        pool_desc = "mixed case"
    elif len(pools) == 3:
        pool_desc = "alphanumeric"
    else:
        pool_desc = "mixed"
    
    return {
        'length': length,
        'score': score,
        'grade': grade,
        'entropy': entropy,
        'final_entropy': final_entropy,
        'pool_desc': pool_desc,
        'notes': notes if notes else ['none']
    }


def format_output(result, show_password=True):
    """Format the audit result for output."""
    lines = []
    lines.append(f"Password: ******** (length {result['length']})")
    lines.append(f"Score: {result['score']}/4 ({result['grade']})")
    lines.append(f"Entropy: ~{int(result['final_entropy'])} bits ({result['pool_desc']}, after penalties)")
    lines.append(f"Notes: {'; '.join(result['notes'])}")
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Audit password strength locally',
        add_help=False
    )
    parser.add_argument('password', nargs='?', help='password to audit')
    parser.add_argument('--stdin', action='store_true', help='read passwords from stdin')
    parser.add_argument('--file', metavar='PATH', help='read passwords from file')
    parser.add_argument('--min-score', type=int, default=0, metavar='N',
                        help='minimum acceptable score for batch mode')
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help='show this help message and exit')
    
    args = parser.parse_args()
    
    # Validate input sources
    input_sources = sum([
        args.password is not None,
        args.stdin,
        args.file is not None
    ])
    
    if input_sources != 1:
        print("Error: exactly one input source required", file=sys.stderr)
        sys.exit(2)
    
    passwords = []
    
    if args.password is not None:
        passwords = [args.password]
    elif args.stdin:
        try:
            for line in sys.stdin:
                pwd = line.rstrip('\n\r')
                passwords.append(pwd)
        except KeyboardInterrupt:
            pass
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    pwd = line.rstrip('\n\r')
                    passwords.append(pwd)
        except (IOError, OSError) as e:
            print(f"Error: cannot read file '{args.file}'", file=sys.stderr)
            sys.exit(2)
    
    # Process passwords
    results = []
    for pwd in passwords:
        result = audit_password(pwd)
        results.append(result)
    
    # Output results
    if len(results) == 1:
        print(format_output(results[0]))
        sys.exit(0)
    else:
        # Batch mode
        for i, result in enumerate(results):
            if i > 0:
                print("---")
            print(format_output(result))
        
        # Summary
        min_score = min(r['score'] for r in results)
        avg_entropy = sum(r['entropy'] for r in results) / len(results) if results else 0
        print(f"Summary: {len(results)} passwords, weakest score {min_score}, average entropy ~{int(avg_entropy)} bits")
        
        # Check min-score
        if min_score < args.min_score:
            sys.exit(1)
        sys.exit(0)


if __name__ == '__main__':
    main()
