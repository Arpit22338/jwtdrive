#!/usr/bin/env python3
"""
PHASE 1 - PLAN

Modules (stdlib):
- argparse: build a professional CLI interface with clear help text.
- concurrent.futures: ThreadPoolExecutor for concurrent requests.
- dataclasses: simple structure for result records.
- json: parse JSON responses safely.
- os: file path handling and output placement.
- re: extract likely JWKS/key URLs from responses.
- threading: Lock to protect shared result collection.
- urllib.parse: urljoin for relative jwks_uri resolution.

Modules (pip):
- requests: HTTP client with SSL verification control and timeouts.
- cryptography: parse X.509 certs and export public keys to PEM.
- python-jose[cryptography]: convert JWK to PEM with crypto backend.
- rich: all terminal output (tables, panels, progress, colored status).

CLI interface (argparse):
- -t,  --target (str, default: None)
  Help: Target base URL to brute-force (e.g. https://target.com)
- -pu, --pubkey-url (str, default: None)
  Help: Skip brute-force and fetch a known public key URL directly
- -o,  --output (str, default: <domain>.pem)
  Help: Output filename for the saved PEM public key
- -w,  --wordlist (str, default: None)
  Help: Path to a custom wordlist file (one path per line)
- -T,  --threads (int, default: 10)
  Help: Number of concurrent threads for brute-force requests
- -k,  --no-verify (bool flag, default: False)
  Help: Disable SSL certificate verification (useful for self-signed targets)
- -v,  --verbose (bool flag, default: False)
  Help: Show all attempted paths including failures
- --discover (bool flag, default: False)
  Help: Discover keys by scraping root HTML/JS before brute-force
- --follow-hosts (bool flag, default: False)
  Help: Allow following key URLs on external hosts
- --max-candidates (int, default: 40)
  Help: Maximum candidate URLs to follow per response
- --secret-hunt (bool flag, default: False)
  Help: Scan responses for likely JWT shared secrets (heuristic)

Internal functions:
- build_arg_parser() -> argparse.ArgumentParser
  Purpose: Build and return the CLI parser with professional help text.
- load_wordlist(path: str | None) -> list[str]
  Purpose: Load custom wordlist if provided, else return built-in list.
- normalize_base_url(target: str) -> str
  Purpose: Ensure a target base URL has a scheme and no trailing slash.
- preflight_connectivity(url: str, verify: bool, timeout: int) -> bool
  Purpose: Check reachability and handle fatal connection errors early.
- fetch_url(url: str, verify: bool, timeout: int) -> requests.Response | None
  Purpose: Perform a GET request with error handling.
- detect_openid_config(data: dict) -> str | None
  Purpose: Extract jwks_uri from openid-configuration responses.
- extract_candidate_urls(text: bytes, base_url: str, allow_external: bool,
  max_candidates: int) -> list[str]
  Purpose: Pull likely JWKS/key URLs from response bodies for follow-up fetches.
- extract_script_urls(text: bytes, base_url: str, allow_external: bool,
  max_candidates: int) -> list[str]
  Purpose: Pull JavaScript asset URLs for scraping JWKS/key references.
- find_possible_secrets(text: bytes) -> list[str]
  Purpose: Identify likely shared secret values for HS256 tokens.
- root_domain(host: str) -> str
  Purpose: Extract a root domain for subdomain expansion.
- build_idp_bases(target: str, allow_external: bool) -> list[str]
  Purpose: Build candidate IdP base URLs for discovery.
- seed_discovery(base_urls: list[str], output: str, verify: bool, timeout: int,
  visited: set[str], results: list[Result], lock: threading.Lock,
  console: rich.console.Console, verbose: bool, allow_external: bool,
  max_candidates: int, secret_hunt: bool) -> None
  Purpose: Fetch likely IdP endpoints before brute-force.
- jwk_set_to_pems(jwk_set: dict) -> list[bytes]
  Purpose: Convert all keys in a JWK Set to PEM-encoded public keys.
- extract_pem_from_cert(content: bytes) -> bytes | None
  Purpose: Extract a public key from X.509 PEM or DER cert content.
- save_pem(pem: bytes, path: str) -> str
  Purpose: Write PEM bytes to disk and return the saved path.
- default_output_name(target_url: str) -> str
  Purpose: Build a default PEM filename from the target hostname.
- process_response(url: str, display_path: str, status: int, content: bytes,
                   content_type: str, output: str, verify: bool, timeout: int,
                   visited: set[str],
                   results: list[Result], lock: threading.Lock,
                   console: rich.console.Console, verbose: bool) -> None
  Purpose: Detect key format, convert, save, and record results.
- brute_force(target: str, paths: list[str], threads: int, output: str,
              verify: bool, timeout: int, verbose: bool,
              console: rich.console.Console) -> list[Result]
  Purpose: Concurrently request all paths and collect results safely.
- run_direct(url: str, output: str, verify: bool, timeout: int,
             verbose: bool, console: rich.console.Console) -> list[Result]
  Purpose: Fetch a single URL directly and process results.
- render_summary(results: list[Result], console: rich.console.Console) -> None
  Purpose: Render a summary table with PATH, HTTP STATUS, KEY TYPE, SAVED AS.
- ensure_dependencies(console: rich.console.Console) -> bool
  Purpose: Import third-party dependencies lazily and report missing modules.
- main() -> int
  Purpose: Orchestrate CLI parsing, execution, and output.

Built-in wordlist (grouped by category):
Standard JWKS:
  /.well-known/jwks.json
  /.well-known/jwks
  /jwks.json
  /jwks
  /jwks/keys
  /.well-known/openid-configuration
  /.well-known/oauth-authorization-server
  /.well-known/openid-configuration/jwks
  /.well-known/keys

OAuth / OpenID:
  /oauth/jwks
  /oauth2/jwks
  /oauth/keys
  /oauth2/keys
  /oauth/v1/keys
  /oauth/v2/keys
  /oauth2/v1/keys
  /oauth2/v2/keys
  /oauth2/v3/certs
  /oauth/discovery/keys
  /oauth2/discovery/keys
  /oauth/token_keys
  /oauth2/token_keys

Auth generic:
  /auth/jwks
  /auth/jwks.json
  /auth/keys
  /auth/public-key
  /auth/public_key
  /auth/certs
  /auth/v1/jwks
  /auth/v2/jwks
  /auth/realms/master/protocol/openid-connect/certs
  /auth/realms/app/protocol/openid-connect/certs

API paths:
  /api/jwks
  /api/jwks.json
  /api/keys
  /api/public-key
  /api/public_key
  /api/auth/keys
  /api/auth/jwks
  /api/auth/jwks.json
  /api/auth/public-key
  /api/v1/auth/public-key
  /api/v1/jwks
  /api/v1/keys
  /api/v2/jwks
  /api/v2/keys
  /api/v1/auth/jwks
  /api/v2/auth/jwks
  /api/v1/certs
  /api/v2/certs
  /api/security/keys
  /api/security/jwks

Public key direct:
  /public-key
  /public_key
  /public-key.pem
  /public_key.pem
  /pubkey
  /pubkey.pem
  /rsa-public-key
  /rsa_public_key
  /signing-key
  /signing_key
  /signing-keys
  /signing_keys

Certs:
  /certs
  /cert
  /certificates
  /.well-known/certs
  /.well-known/cert
  /tls.crt
  /server.crt
  /public.crt
  /public.pem

Keycloak:
  /realms/master/protocol/openid-connect/certs
  /realms/app/protocol/openid-connect/certs
  /realms/springboot/protocol/openid-connect/certs
  /realms/demo/protocol/openid-connect/certs
  /realms/internal/protocol/openid-connect/certs
  /realms/external/protocol/openid-connect/certs
  /realms/production/protocol/openid-connect/certs
  /auth/realms/master/protocol/openid-connect/certs
  /auth/realms/app/protocol/openid-connect/certs

AWS Cognito style:
  /.well-known/jwks.json
  /us-east-1_example/.well-known/jwks.json

Azure AD / Microsoft style:
  /common/discovery/keys
  /common/discovery/v2.0/keys
  /v2.0/.well-known/openid-configuration
  /v1.0/.well-known/openid-configuration
  /tenant/discovery/keys
  /organizations/discovery/keys

Firebase / Google style:
  /robot/v1/metadata/x509/securetoken@system.gserviceaccount.com
  /v1/jwks

Okta style:
  /v1/keys
  /oauth2/v1/keys
  /oauth2/default/v1/keys
  /oauth2/aus0/v1/keys

Connect / Identity:
  /connect/jwks_uri
  /connect/keys
  /identity/.well-known/openid-configuration
  /identity/connect/jwks_uri
  /identity/jwks
  /identity/keys
  /oidc/keys
  /oidc/jwks
  /oidc/jwks.json
  /oidc/certs
  /oidc/.well-known/openid-configuration

Spring Boot / Java common:
  /spring/jwks.json
  /auth/token/jwks
  /sso/jwks
  /sso/keys
  /sso/oauth/jwks

Node / Express common:
  /api/auth/verify/jwks
  /api/auth/certs
  /.well-known/pki-validation/jwks.json

Misc framework paths:
  /v1/auth/certs
  /v1/auth/keys
  /v1/auth/jwks
  /v2/auth/keys
  /v2/auth/jwks
  /security/jwks
  /security/keys
  /security/certs
  /service/jwks
  /service/keys
  /token/keys
  /token/jwks
  /token/certs
  /keys/public
  /keys/signing
  /admin/jwks
  /admin/keys
  /admin/public-key
  /internal/jwks
  /internal/keys
  /system/jwks
  /system/keys

Key detection and conversion logic:
- openid-configuration JSON: if a jwks_uri is present, fetch it and parse as JWK Set.
  The jwks_uri may be relative; resolve with urljoin. Track visited URLs to avoid loops.
- JWK Set: if JSON contains keys[], convert each key to PEM using python-jose
  (jwk.construct -> to_pem). Save each key as pubkey_1.pem, pubkey_2.pem, etc.
- Raw PEM: if body begins with -----BEGIN and is not a certificate, save directly.
- X.509 Certificate (PEM or DER): load cert with cryptography, extract public key,
  serialize to PEM using SubjectPublicKeyInfo.

Threading model:
- ThreadPoolExecutor with configurable workers (default 10).
- A shared results list is protected by a threading.Lock.
- Each worker fetches a path, processes response, and appends a Result record.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

if TYPE_CHECKING:
    from rich.console import Console


BUILTIN_WORDLIST = [
    "/.well-known/jwks.json",
    "/.well-known/jwks",
    "/jwks.json",
    "/jwks",
    "/jwks/keys",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration/jwks",
    "/.well-known/keys",
    "/oauth/jwks",
    "/oauth2/jwks",
    "/oauth/keys",
    "/oauth2/keys",
    "/oauth/v1/keys",
    "/oauth/v2/keys",
    "/oauth2/v1/keys",
    "/oauth2/v2/keys",
    "/oauth2/v3/certs",
    "/oauth/discovery/keys",
    "/oauth2/discovery/keys",
    "/oauth/token_keys",
    "/oauth2/token_keys",
    "/auth/jwks",
    "/auth/jwks.json",
    "/auth/keys",
    "/auth/public-key",
    "/auth/public_key",
    "/auth/certs",
    "/auth/v1/jwks",
    "/auth/v2/jwks",
    "/auth/realms/master/protocol/openid-connect/certs",
    "/auth/realms/app/protocol/openid-connect/certs",
    "/api/jwks",
    "/api/jwks.json",
    "/api/keys",
    "/api/public-key",
    "/api/public_key",
    "/api/auth/keys",
    "/api/auth/jwks",
    "/api/auth/jwks.json",
    "/api/auth/public-key",
    "/api/v1/auth/public-key",
    "/api/v1/jwks",
    "/api/v1/keys",
    "/api/v2/jwks",
    "/api/v2/keys",
    "/api/v1/auth/jwks",
    "/api/v2/auth/jwks",
    "/api/v1/certs",
    "/api/v2/certs",
    "/api/security/keys",
    "/api/security/jwks",
    "/public-key",
    "/public_key",
    "/public-key.pem",
    "/public_key.pem",
    "/pubkey",
    "/pubkey.pem",
    "/rsa-public-key",
    "/rsa_public_key",
    "/signing-key",
    "/signing_key",
    "/signing-keys",
    "/signing_keys",
    "/certs",
    "/cert",
    "/certificates",
    "/.well-known/certs",
    "/.well-known/cert",
    "/tls.crt",
    "/server.crt",
    "/public.crt",
    "/public.pem",
    "/realms/master/protocol/openid-connect/certs",
    "/realms/app/protocol/openid-connect/certs",
    "/realms/springboot/protocol/openid-connect/certs",
    "/realms/demo/protocol/openid-connect/certs",
    "/realms/internal/protocol/openid-connect/certs",
    "/realms/external/protocol/openid-connect/certs",
    "/realms/production/protocol/openid-connect/certs",
    "/auth/realms/master/protocol/openid-connect/certs",
    "/auth/realms/app/protocol/openid-connect/certs",
    "/.well-known/jwks.json",
    "/us-east-1_example/.well-known/jwks.json",
    "/common/discovery/keys",
    "/common/discovery/v2.0/keys",
    "/v2.0/.well-known/openid-configuration",
    "/v1.0/.well-known/openid-configuration",
    "/tenant/discovery/keys",
    "/organizations/discovery/keys",
    "/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
    "/v1/jwks",
    "/v1/keys",
    "/oauth2/v1/keys",
    "/oauth2/default/v1/keys",
    "/oauth2/aus0/v1/keys",
    "/connect/jwks_uri",
    "/connect/keys",
    "/identity/.well-known/openid-configuration",
    "/identity/connect/jwks_uri",
    "/identity/jwks",
    "/identity/keys",
    "/oidc/keys",
    "/oidc/jwks",
    "/oidc/jwks.json",
    "/oidc/certs",
    "/oidc/.well-known/openid-configuration",
    "/spring/jwks.json",
    "/auth/token/jwks",
    "/sso/jwks",
    "/sso/keys",
    "/sso/oauth/jwks",
    "/api/auth/verify/jwks",
    "/api/auth/certs",
    "/.well-known/pki-validation/jwks.json",
    "/v1/auth/certs",
    "/v1/auth/keys",
    "/v1/auth/jwks",
    "/v2/auth/keys",
    "/v2/auth/jwks",
    "/security/jwks",
    "/security/keys",
    "/security/certs",
    "/service/jwks",
    "/service/keys",
    "/token/keys",
    "/token/jwks",
    "/token/certs",
    "/keys/public",
    "/keys/signing",
    "/admin/jwks",
    "/admin/keys",
    "/admin/public-key",
    "/internal/jwks",
    "/internal/keys",
    "/system/jwks",
    "/system/keys",
]


DEFAULT_TIMEOUT = 5
DEFAULT_HEADERS = {
    "User-Agent": "jwtdrive/1.0",
    "Accept": "application/json,*/*;q=0.8",
}
MAX_CANDIDATES = 40
MAX_DISCOVER_REQUESTS = 50
_discover_count: int = 0
_discover_lock: threading.Lock = threading.Lock()


@dataclass
class Result:
    path: str
    status: int | str
    key_type: str
    saved_as: str


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jwtdrive",
        description="Brute-force JWT public key endpoints and extract PEM keys for jwt_tool workflows.",
    )
    parser.add_argument(
        "-t",
        "--target",
        help="Target base URL to brute-force (e.g. https://target.com)",
    )
    parser.add_argument(
        "-pu",
        "--pubkey-url",
        help="Skip brute-force and fetch a known public key URL directly",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output filename for the saved PEM public key (default: <domain>.pem)",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        help="Path to a custom wordlist file (one path per line)",
    )
    parser.add_argument(
        "-T",
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads for brute-force requests",
    )
    parser.add_argument(
        "-k",
        "--no-verify",
        action="store_true",
        help="Disable SSL certificate verification (useful for self-signed targets)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show all attempted paths including failures",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Discover keys by scraping root HTML/JS before brute-force",
    )
    parser.add_argument(
        "--follow-hosts",
        action="store_true",
        help="Allow following key URLs on external hosts",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=MAX_CANDIDATES,
        help="Maximum candidate URLs to follow per response",
    )
    return parser


def ensure_dependencies(console: "Console") -> bool:
    try:
        import requests
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from jose import jwk
        from rich.console import Console
        from rich.panel import Panel
        from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
        from rich.table import Table

        globals().update(
            {
                "requests": requests,
                "x509": x509,
                "serialization": serialization,
                "jwk": jwk,
                "Console": Console,
                "Panel": Panel,
                "Progress": Progress,
                "BarColumn": BarColumn,
                "SpinnerColumn": SpinnerColumn,
                "TextColumn": TextColumn,
                "Table": Table,
            }
        )
        return True
    except ModuleNotFoundError as exc:
        console.print(
            f"[red]Missing dependency: {exc.name}.[/red] Install with: pip install -r requirements.txt"
        )
        return False


def load_wordlist(path: str | None) -> list[str]:
    if not path:
        return BUILTIN_WORDLIST
    wordlist: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            entry = line.strip()
            if entry:
                wordlist.append(entry)
    return wordlist


def normalize_base_url(target: str) -> str:
    if "//" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc or parsed.path
    if not netloc:
        return target.rstrip("/")
    return f"{scheme}://{netloc}".rstrip("/")


def preflight_connectivity(url: str, verify: bool, timeout: int, console: "Console") -> bool:
    try:
        requests.get(
            url,
            timeout=timeout,
            verify=verify,
            allow_redirects=True,
            headers=DEFAULT_HEADERS,
        )
        return True
    except requests.exceptions.SSLError:
        console.print("[yellow]SSL error encountered. Try -k to disable verification.[/yellow]")
        return True
    except requests.exceptions.ConnectionError:
        console.print("[red]Connection failed. Host unreachable or DNS resolution failed.[/red]")
        return False
    except requests.exceptions.Timeout:
        return True
    except requests.exceptions.RequestException:
        console.print("[red]Connection failed due to an unexpected network error.[/red]")
        return False


def fetch_url(url: str, verify: bool, timeout: int) -> "requests.Response | None":
    try:
        return requests.get(url, timeout=(3, timeout), verify=verify, headers=DEFAULT_HEADERS)
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.SSLError:
        raise
    except requests.exceptions.ConnectionError:
        raise
    except requests.exceptions.RequestException:
        return None


def detect_openid_config(data: dict) -> str | None:
    jwks_uri = data.get("jwks_uri") or data.get("jwksUri")
    if isinstance(jwks_uri, str) and jwks_uri.strip():
        return jwks_uri.strip()
    return None


def extract_candidate_urls(
    text: bytes,
    base_url: str,
    allow_external: bool,
    max_candidates: int,
) -> list[str]:
    candidates: list[str] = []
    decoded = text.decode("utf-8", errors="ignore")
    base_host = urlparse(base_url).netloc
    patterns = [
        r"https?://[\w\-\.:]+/[\w\-\./]+",
        r"/[\w\-\./]+",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, decoded):
            if len(candidates) >= max_candidates:
                return candidates
            url = match
            if url.startswith("/"):
                url = urljoin(base_url, url)
            if not allow_external and urlparse(url).netloc and urlparse(url).netloc != base_host:
                continue
            if url not in candidates:
                candidates.append(url)
    filtered = [c for c in candidates if any(k in c.lower() for k in ("jwks", "jwk", "keys", "cert", "openid"))]
    return filtered[:max_candidates]


def extract_script_urls(
    text: bytes,
    base_url: str,
    allow_external: bool,
    max_candidates: int,
) -> list[str]:
    decoded = text.decode("utf-8", errors="ignore")
    script_urls: list[str] = []
    base_host = urlparse(base_url).netloc
    for match in re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", decoded, re.IGNORECASE):
        url = match
        if url.startswith("/"):
            url = urljoin(base_url, url)
        if url.startswith("//"):
            url = "https:" + url
        if not allow_external and urlparse(url).netloc and urlparse(url).netloc != base_host:
            continue
        if url not in script_urls:
            script_urls.append(url)
        if len(script_urls) >= max_candidates:
            break
    return script_urls


def root_domain(host: str) -> str:
    if not host:
        return ""
    host = host.split(":")[0].lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def build_idp_bases(target: str, allow_external: bool) -> list[str]:
    bases: list[str] = []
    parsed = urlparse(target)
    scheme = parsed.scheme or "https"
    host = parsed.netloc or parsed.path
    root = root_domain(host)
    subdomains = ["auth", "login", "id", "identity", "sso", "oauth", "oidc"]
    for sub in subdomains:
        if root:
            bases.append(f"{scheme}://{sub}.{root}")
        bases.append(f"{scheme}://{sub}.{host}")

    if allow_external:
        bases.extend(
            [
                "https://login.microsoftonline.com/common",
                "https://login.microsoftonline.com/organizations",
                "https://login.microsoftonline.com/consumers",
                "https://accounts.google.com",
            ]
        )
    return list(dict.fromkeys(bases))


def seed_discovery(
    base_urls: list[str],
    output: str,
    verify: bool,
    timeout: int,
    visited: set[str],
    results: list[Result],
    lock: threading.Lock,
    console: "Console",
    verbose: bool,
    allow_external: bool,
    max_candidates: int,
) -> None:
    seed_paths = [
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
        "/.well-known/oauth-authorization-server",
        "/v2.0/.well-known/openid-configuration",
        "/v1.0/.well-known/openid-configuration",
        "/.well-known/keys",
        "/oauth2/v1/keys",
        "/oauth2/default/v1/keys",
        "/oauth2/v1/keys",
    ]
    urls_to_fetch = []
    for base in base_urls:
        for path in seed_paths:
            url = base.rstrip("/") + path
            with lock:
                if url in visited:
                    continue
                visited.add(url)
            urls_to_fetch.append(url)

    def seed_worker(seed_url: str) -> None:
        try:
            response = fetch_url(seed_url, verify=verify, timeout=timeout)
        except requests.exceptions.SSLError:
            return
        except requests.exceptions.ConnectionError:
            return
        if response is None:
            return
        process_response(
            seed_url,
            seed_url,
            response.status_code,
            response.content,
            response.headers.get("content-type", ""),
            output,
            verify,
            timeout,
            visited,
            results,
            lock,
            console,
            verbose,
            allow_external,
            max_candidates,
        )

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    for url in urls_to_fetch:
        executor.submit(seed_worker, url)
    executor.shutdown(wait=False)


def jwk_set_to_pems(jwk_set: dict) -> list[bytes]:
    keys = jwk_set.get("keys")
    if not isinstance(keys, list):
        return []
    pem_list: list[bytes] = []
    for key_dict in keys:
        if not isinstance(key_dict, dict):
            continue
        key_obj = jwk.construct(key_dict)
        pem_list.append(key_obj.to_pem())
    return pem_list


def extract_pem_from_cert(content: bytes) -> bytes | None:
    try:
        cert = x509.load_pem_x509_certificate(content)
    except ValueError:
        try:
            cert = x509.load_der_x509_certificate(content)
        except ValueError:
            return None
    public_key = cert.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def save_pem(pem: bytes, path: str) -> str:
    with open(path, "wb") as handle:
        handle.write(pem)
    return path


def default_output_name(target_url: str) -> str:
    parsed = urlparse(target_url)
    host = parsed.netloc or parsed.path
    host = host.split(":")[0]
    host = host.strip().lower()
    host = host.replace("..", ".").strip(".")
    if not host:
        host = "pubkey"
    return f"{host}.pem"


def process_response(
    url: str,
    display_path: str,
    status: int,
    content: bytes,
    content_type: str,
    output: str,
    verify: bool,
    timeout: int,
    visited: set[str],
    results: list[Result],
    lock: threading.Lock,
    console: "Console",
    verbose: bool,
    allow_external: bool,
    max_candidates: int,
) -> None:
    global _discover_count
    if status != 200:
        if verbose:
            with lock:
                results.append(Result(display_path, status, "-", "-"))
        return
    if not content:
        if verbose:
            with lock:
                results.append(Result(display_path, status, "empty", "-"))
        return

    text_sample = content[:2048]
    key_type = "unknown"

    content_type = (content_type or "").lower()
    html_marker = b"<html" in text_sample.lower() or text_sample.startswith(b"<!doctype html")
    if "text/html" in content_type or html_marker:
        for script_url in extract_script_urls(content, url, allow_external, max_candidates):
            with lock:
                if script_url in visited:
                    continue
                visited.add(script_url)
            try:
                response = fetch_url(script_url, verify=verify, timeout=timeout)
            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.ConnectionError:
                raise
            if response is None:
                continue
            process_response(
                script_url,
                script_url,
                response.status_code,
                response.content,
                response.headers.get("content-type", ""),
                output,
                verify,
                timeout,
                visited,
                results,
                lock,
                console,
                verbose,
                allow_external,
                max_candidates,
            )
        if verbose:
            with lock:
                results.append(Result(display_path, status, "html", "-"))
        return

    data = None
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            data = json.loads(content.decode(encoding))
            break
        except (UnicodeDecodeError, json.JSONDecodeError):
            data = None

    if isinstance(data, dict):
        jwks_uri = detect_openid_config(data)
        if jwks_uri:
            resolved = jwks_uri
            if not jwks_uri.startswith("http://") and not jwks_uri.startswith("https://"):
                resolved = urljoin(url, jwks_uri)
            with lock:
                results.append(Result(display_path, status, "openid-configuration", resolved))
                should_fetch = resolved not in visited
                if should_fetch:
                    visited.add(resolved)
            if should_fetch:
                try:
                    response = fetch_url(resolved, verify=verify, timeout=timeout)
                except requests.exceptions.SSLError:
                    console.print(
                        f"[yellow]SSL error for {resolved}. Try -k to disable verification.[/yellow]"
                    )
                    return
                except requests.exceptions.ConnectionError:
                    console.print("[red]Connection failed. Host unreachable or DNS failed.[/red]")
                    raise
                if response is None:
                    if verbose:
                        with lock:
                            results.append(Result(resolved, "timeout", "-", "-"))
                    return
                process_response(
                    resolved,
                    resolved,
                    response.status_code,
                    response.content,
                    response.headers.get("content-type", ""),
                    output,
                    verify,
                    timeout,
                    visited,
                    results,
                    lock,
                    console,
                    verbose,
                    allow_external,
                    max_candidates,
                )
            return

        for key in ("jwks", "jwks_json", "jwksJson", "jwks_keys"):
            jwks_value = data.get(key)
            if isinstance(jwks_value, dict) and "keys" in jwks_value:
                data = jwks_value
                break

        if "keys" in data:
            pem_list = []
            try:
                pem_list = jwk_set_to_pems(data)
            except Exception:
                pem_list = []
            if pem_list:
                for idx, pem in enumerate(pem_list, start=1):
                    saved_name = output
                    if len(pem_list) > 1:
                        base, ext = os.path.splitext(output)
                        saved_name = f"{base}_{idx}{ext or '.pem'}"
                    save_pem(pem, saved_name)
                    with lock:
                        results.append(Result(display_path, status, "jwk", saved_name))
                    console.print(
                        Panel.fit(
                            f"[green][+] Key saved -> ./{saved_name}[/green]\n"
                            "[green][+] Ready for jwt_tool. Run:[/green]\n"
                            f"    jwt_tool <your_token> -X k -pk {saved_name}",
                            title="jwtdrive",
                            border_style="green",
                        )
                    )
                return

    if text_sample.startswith(b"-----BEGIN"):
        if b"CERTIFICATE" in text_sample:
            pem = extract_pem_from_cert(content)
            if pem:
                save_pem(pem, output)
                with lock:
                    results.append(Result(display_path, status, "x509", output))
                console.print(
                    Panel.fit(
                        f"[green][+] Key saved -> ./{output}[/green]\n"
                        "[green][+] Ready for jwt_tool. Run:[/green]\n"
                        f"    jwt_tool <your_token> -X k -pk {output}",
                        title="jwtdrive",
                        border_style="green",
                    )
                )
                return
        save_pem(content, output)
        with lock:
            results.append(Result(display_path, status, "pem", output))
        console.print(
            Panel.fit(
                f"[green][+] Key saved -> ./{output}[/green]\n"
                "[green][+] Ready for jwt_tool. Run:[/green]\n"
                f"    jwt_tool <your_token> -X k -pk {output}",
                title="jwtdrive",
                border_style="green",
            )
        )
        return

    pem = extract_pem_from_cert(content)
    if pem:
        save_pem(pem, output)
        with lock:
            results.append(Result(display_path, status, "x509", output))
        console.print(
            Panel.fit(
                f"[green][+] Key saved -> ./{output}[/green]\n"
                "[green][+] Ready for jwt_tool. Run:[/green]\n"
                f"    jwt_tool <your_token> -X k -pk {output}",
                title="jwtdrive",
                border_style="green",
            )
        )
        return

    if verbose:
        key_type = "unknown"
        with lock:
            results.append(Result(display_path, status, key_type, "-"))

    should_follow = False
    with _discover_lock:
        if _discover_count < MAX_DISCOVER_REQUESTS:
            should_follow = True
    if not should_follow:
        return
    for candidate in extract_candidate_urls(content, url, allow_external, max_candidates):
        with _discover_lock:
            _discover_count += 1
        with lock:
            if candidate in visited:
                continue
            visited.add(candidate)
        try:
            response = fetch_url(candidate, verify=verify, timeout=timeout)
        except requests.exceptions.SSLError:
            return
        except requests.exceptions.ConnectionError:
            raise
        if response is None:
            continue
        process_response(
            candidate,
            candidate,
            response.status_code,
            response.content,
            response.headers.get("content-type", ""),
            output,
            verify,
            timeout,
            visited,
            results,
            lock,
            console,
            verbose,
            allow_external,
            max_candidates,
        )


def brute_force(
    target: str,
    paths: list[str],
    threads: int,
    output: str,
    verify: bool,
    timeout: int,
    verbose: bool,
    console: "Console",
    discover: bool,
    allow_external: bool,
    max_candidates: int,
) -> list[Result]:
    results: list[Result] = []
    lock = threading.Lock()
    visited: set[str] = set()

    if discover:
        idp_bases = build_idp_bases(target, allow_external)
        seed_discovery(
            idp_bases,
            output,
            verify,
            timeout,
            visited,
            results,
            lock,
            console,
            verbose,
            allow_external,
            max_candidates,
        )
        try:
            root_response = fetch_url(target + "/", verify=verify, timeout=timeout)
        except requests.exceptions.SSLError:
            console.print(
                f"[yellow]SSL error for {target}/. Try -k to disable verification.[/yellow]"
            )
            root_response = None
        except requests.exceptions.ConnectionError:
            console.print("[red]Connection failed. Host unreachable or DNS failed.[/red]")
            raise
        if root_response is not None:
            try:
                process_response(
                    target + "/",
                    "/",
                    root_response.status_code,
                    root_response.content,
                    root_response.headers.get("content-type", ""),
                    output,
                    verify,
                    timeout,
                    visited,
                    results,
                    lock,
                    console,
                    verbose,
                    allow_external,
                    max_candidates,
                    secret_hunt,
                )
            except Exception:
                if verbose:
                    results.append(Result("/", root_response.status_code, "error", "-"))

    def worker(path: str) -> None:
        url = f"{target}{path}"
        try:
            response = fetch_url(url, verify=verify, timeout=timeout)
        except requests.exceptions.SSLError:
            console.print(
                f"[yellow]SSL error for {url}. Try -k to disable verification.[/yellow]"
            )
            return
        except requests.exceptions.ConnectionError:
            console.print("[red]Connection failed. Host unreachable or DNS failed.[/red]")
            raise

        if response is None:
            if verbose:
                with lock:
                    results.append(Result(path, "timeout", "-", "-"))
            return

        if response.status_code == 429:
            console.print(
                "[yellow]429 Too Many Requests. Consider lowering --threads.[/yellow]"
            )
        if verbose:
            console.print(f"[cyan]{path}[/cyan] [{response.status_code}]")
        try:
            process_response(
                url,
                path,
                response.status_code,
                response.content,
                response.headers.get("content-type", ""),
                output,
                verify,
                timeout,
                visited,
                results,
                lock,
                console,
                verbose,
                allow_external,
                max_candidates,
                secret_hunt,
            )
        except Exception:
            if verbose:
                with lock:
                    results.append(Result(path, response.status_code, "error", "-"))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Brute-forcing", total=len(paths))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for path in paths:
                futures.append(executor.submit(worker, path))
            for future in futures:
                try:
                    future.result()
                except requests.exceptions.ConnectionError:
                    raise
                finally:
                    progress.advance(task)

    return results


def run_direct(
    url: str,
    output: str,
    verify: bool,
    timeout: int,
    verbose: bool,
    console: "Console",
    allow_external: bool,
    max_candidates: int,
    secret_hunt: bool,
) -> list[Result]:
    results: list[Result] = []
    lock = threading.Lock()
    visited: set[str] = {url}

    try:
        response = fetch_url(url, verify=verify, timeout=timeout)
    except requests.exceptions.SSLError:
        console.print(
            f"[yellow]SSL error for {url}. Try -k to disable verification.[/yellow]"
        )
        return results
    except requests.exceptions.ConnectionError:
        console.print("[red]Connection failed. Host unreachable or DNS failed.[/red]")
        return results

    if response is None:
        if verbose:
            results.append(Result(url, "timeout", "-", "-"))
        return results

    if response.status_code == 429:
        console.print("[yellow]429 Too Many Requests. Consider lowering --threads.[/yellow]")

    if verbose:
        console.print(f"[cyan]{url}[/cyan] [{response.status_code}]")

    try:
        process_response(
            url,
            url,
            response.status_code,
            response.content,
            response.headers.get("content-type", ""),
            output,
            verify,
            timeout,
            visited,
            results,
            lock,
            console,
            verbose,
            allow_external,
            max_candidates,
        )
    except Exception:
        if verbose:
            results.append(Result(url, response.status_code, "error", "-"))
    return results


def render_summary(results: list[Result], console: "Console") -> None:
    if not results:
        console.print("[yellow]No results to summarize.[/yellow]")
        return
    table = Table(title="jwtdrive summary")
    table.add_column("PATH", style="cyan", overflow="fold")
    table.add_column("HTTP STATUS", style="magenta")
    table.add_column("KEY TYPE", style="green")
    table.add_column("SAVED AS", style="yellow", overflow="fold")
    for result in results:
        table.add_row(result.path, str(result.status), result.key_type, result.saved_as)
    console.print(table)


def main() -> int:
    try:
        from rich.console import Console
    except ModuleNotFoundError:
        print("Missing dependency: rich. Install with: pip install -r requirements.txt")
        return 1

    console = Console()
    parser = build_arg_parser()
    args = parser.parse_args()

    if not args.target and not args.pubkey_url:
        console.print("[red]Error: --target or --pubkey-url is required.[/red]")
        return 2
    if args.target and args.pubkey_url:
        console.print("[red]Error: Use --target or --pubkey-url, not both.[/red]")
        return 2

    verify = not args.no_verify

    if not ensure_dependencies(console):
        return 1

    output_name = args.output
    if not output_name:
        if args.pubkey_url:
            output_name = default_output_name(args.pubkey_url)
        else:
            output_name = default_output_name(args.target)

    if args.pubkey_url:
        results = run_direct(
            args.pubkey_url,
            output_name,
            verify,
            DEFAULT_TIMEOUT,
            args.verbose,
            console,
            args.follow_hosts,
            args.max_candidates,
        )
        render_summary(results, console)
        return 0

    target = normalize_base_url(args.target)
    if not preflight_connectivity(target, verify, DEFAULT_TIMEOUT, console):
        return 1

    try:
        paths = load_wordlist(args.wordlist)
    except OSError:
        console.print("[red]Error: Unable to read wordlist file.[/red]")
        return 1

    results: list[Result] = []
    try:
        results = brute_force(
            target,
            paths,
            args.threads,
            output_name,
            verify,
            DEFAULT_TIMEOUT,
            args.verbose,
            console,
            args.discover,
            args.follow_hosts,
            args.max_candidates,
        )
    except KeyboardInterrupt:
        pass
    except requests.exceptions.ConnectionError:
        return 1

    render_summary(results, console)
    if not results:
        console.print("[yellow]No keys found on target.[/yellow]")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        console = Console()
        console.print("\n[yellow]Interrupted. Exiting.[/yellow]")
