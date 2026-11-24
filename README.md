# passcheck

Audit password strength locally — entropy estimate, common-pattern detection, and a 0–4 grade — with no network access and no dependencies. For checking your own passwords, or batch-auditing a list you generated, before you trust them.

## Quickstart

```
python3 passcheck.py --help
python3 passcheck.py "some password to test"
```

## Usage

```
usage: passcheck.py [--stdin] [--file PATH] [--min-score N] [-h] [password]

Audit password strength locally

positional arguments:
  password       password to audit

options:
  --stdin        read passwords from stdin
  --file PATH    read passwords from file
  --min-score N  minimum acceptable score for batch mode
  -h, --help     show this help message and exit
```

The password itself is never printed — only its length, score, estimated entropy, and the weaknesses found (dictionary words, keyboard sequences, repeats, year-like runs, single character class).

## Examples

```
$ python3 passcheck.py "Sunshine2024!"
Password: ******** (length 13)
Score: 2/4 (Fair)
Entropy: ~55 bits (mixed, after penalties)
Notes: contains a dictionary word: "sunshine"; year-like sequence: 2024

$ printf 'abc\nStr0ng!Passw0rdXYZ\n' | python3 passcheck.py --stdin --min-score 2
...
Summary: 2 passwords, weakest score 0, average entropy ~66 bits
(exit code 1, because one password scored below 2)
```

## Configuration

None — all options are command-line flags. Batch mode (`--stdin` / `--file`) reads one password per line; `--min-score N` makes the exit code 1 when any password scores below N, which is handy in scripts.

## Limitations

The entropy figure is a character-pool estimate with rule-based penalties, not a crack-time guarantee; a long passphrase of common words can still be weaker in practice than its estimate. The dictionary list is a small built-in set of very common passwords and words, not a breach database — passcheck never phones home to check one.

## License

MIT — see `LICENSE`.

By Dr. Brent Allen Jensen, Radical Blueprinting Research.

## Support this work

If this tool saved you time, you can support more open work like it:

- **BTC:** `15McijPo79Zx58NGyEf2PvaPtGqGmpztWn`
- **ETH:** `0x8C25164E9234E6A30b8E44485B79c5cE8419cF2B`

Thank you.
