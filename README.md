# jwtdrive

jwtdrive is a focused recon tool for JWT public key discovery. It brute-forces common JWKS and public key endpoints, extracts a compatible PEM public key, and streamlines RS256 -> HS256 algorithm confusion workflows used by jwt_tool during security testing.

## Installation

```bash
git clone <repo-url>
cd jwtdrive
bash install.sh
```

## CLI Flags

- `-t, --target` - Target base URL to brute-force (e.g. `https://target.com`)
  Example: `jwtdrive -t https://target.com`
- `-pu, --pubkey-url` - Skip brute-force and fetch a known public key URL directly
  Example: `jwtdrive -pu https://target.com/.well-known/jwks.json`
- `-o, --output` - Output filename for the saved PEM public key (default: `<domain>.pem`)
  Example: `jwtdrive -t https://target.com -o mykey.pem`
- `-w, --wordlist` - Path to a custom wordlist file (one path per line)
  Example: `jwtdrive -t https://target.com -w custom_wordlist.txt`
- `-T, --threads` - Number of concurrent threads for brute-force requests (default: 10)
  Example: `jwtdrive -t https://target.com -T 20`
- `-k, --no-verify` - Disable SSL certificate verification (useful for self-signed targets)
  Example: `jwtdrive -t https://target.com -k`
- `-v, --verbose` - Show all attempted paths including failures
  Example: `jwtdrive -t https://target.com -v`

## Usage Examples

```bash
jwtdrive -t https://target.com
jwtdrive -t https://target.com -v --threads 20
jwtdrive -t https://target.com -o mykey.pem -w custom_wordlist.txt
jwtdrive -pu https://target.com/.well-known/jwks.json
jwtdrive -t https://target.com -k -v
```

## Using the PEM with jwt_tool

After a successful extraction, jwtdrive prints a ready-to-run jwt_tool command. You can use the saved PEM directly:

```bash
jwt_tool <your_token> -X k -pk example.com.pem
```

## Output Location

The PEM file is saved in the directory where you run the command. By default the filename is the target domain, for example:

```bash
./example.com.pem
```

## Supported Key Formats

- JWK Set (`jwks.json`) - Extracts all keys and saves as `pubkey_1.pem`, `pubkey_2.pem`, etc.
- Raw PEM public key - Saved directly without conversion
- X.509 certificate (PEM or DER) - Extracts the public key and saves as PEM
- OpenID configuration - Follows `jwks_uri` and processes it as a JWK Set
