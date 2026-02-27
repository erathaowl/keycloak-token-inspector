#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.json import JSON
import urllib3

import requests
from environs import Env

urllib3.disable_warnings()
console = Console()


def _find_default_env_file() -> Path:
    # Default: .env next to this script (robust vs Windows cwd differences)
    return Path(__file__).resolve().parent / ".env"


def _parse_verify(value: str) -> Any:
    """
    requests 'verify' parameter can be:
      - True / False
      - path to a CA bundle file
    """
    v = (value or "true").strip()
    vl = v.lower()
    if vl in ("true", "1", "yes", "y", "on"):
        return True
    if vl in ("false", "0", "no", "n", "off"):
        return False
    # otherwise assume it's a path
    return v


def load_config(env_file: Optional[str]) -> Dict[str, Any]:
    env = Env()

    if env_file:
        env_path = Path(env_file).expanduser().resolve()
    else:
        env_path = _find_default_env_file()

    if env_path.exists():
        env.read_env(str(env_path))
        print(f"[env] loaded: {env_path}", file=sys.stderr)
    else:
        print(f"[env] not found: {env_path} (using defaults / OS env)", file=sys.stderr)

    verify = _parse_verify(env.str("KEYCLOAK_VERIFY", "true"))

    return {
        "keycloak_url": env.str("KEYCLOAK_URL", "http://localhost:8080"),
        "base_path": env.str("KEYCLOAK_BASE_PATH", ""),  # e.g. "/auth" for older setups
        "realm": env.str("KEYCLOAK_REALM", "master"),
        "client_id": env.str("KEYCLOAK_CLIENT_ID", "admin-cli"),
        "client_secret": env.str("KEYCLOAK_CLIENT_SECRET", ""),
        "username": env.str("KEYCLOAK_USERNAME", "admin"),
        "password": env.str("KEYCLOAK_PASSWORD", "admin"),
        "verify": verify,
    }

def prompt_for_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Allow user to override client and user parameters loaded from config
    """

    client_id = Prompt.ask(
        "Client ID",
        default=str(cfg["client_id"]),
    )

    client_secret = Prompt.ask(
        "Client Secret (leave empty if public client)",
        default=str(cfg["client_secret"] or ""),
        password=True if cfg["client_secret"] else False,
    )

    username = Prompt.ask(
        "Username",
        default=str(cfg["username"]),
    )

    password = Prompt.ask(
        "Password",
        default=str(cfg["password"]),
        password=True,
    )

    return {
        "keycloak_url": cfg["keycloak_url"],
        "base_path": cfg["base_path"],
        "realm": cfg["realm"],
        "client_id": client_id,
        "client_secret": client_secret,
        "username": username,
        "password": password,
        "verify": cfg["verify"]
    }
    
def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def decode_jwt_no_verify(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Decode JWT header+payload WITHOUT verifying signature.
    Returns (header, payload).
    """
    try:
        import jwt  # PyJWT

        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
        return header, payload
    except Exception:
        parts = token.split(".")
        if len(parts) < 2:
            raise ValueError("Token is not a valid JWT (expected at least 2 dot-separated parts).")
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        return header, payload


def build_token_url(keycloak_url: str, base_path: str, realm: str) -> str:
    base = keycloak_url.rstrip("/")
    bp = (base_path or "").strip()
    if bp and not bp.startswith("/"):
        bp = "/" + bp
    return f"{base}{bp}/realms/{realm}/protocol/openid-connect/token"


def get_token(
        token_url: str,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        verify: Any,
    ) -> Dict[str, Any]:
    data = {
        "grant_type": "password",
        "client_id": client_id,
        "username": username,
        "password": password,
    }
    if client_secret:
        data["client_secret"] = client_secret

    resp = requests.post(
        token_url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
        verify=verify,
    )

    if not resp.ok:
        raise RuntimeError(
            f"Token request failed (HTTP {resp.status_code}).\n"
            f"URL: {token_url}\n"
            f"Response:\n{resp.text}"
        )

    return resp.json()


def main() -> int:
    parser = argparse.ArgumentParser(description="Keycloak token fetch + JWT decode (no verify).")
    parser.add_argument(
        "--env-file",
        default=None,
        help="Path to .env (default: .env next to the script).",
    )

    # CLI overrides (if omitted, values come from .env / defaults)
    parser.add_argument("--keycloak-url", default=None)
    parser.add_argument("--base-path", default=None, help="Optional base path like /auth for older setups")
    parser.add_argument("--realm", default=None)
    # parser.add_argument("--client-id", default=None)
    # parser.add_argument("--client-secret", default=None)
    # parser.add_argument("--username", default=None)
    # parser.add_argument("--password", default=None)
    parser.add_argument("--refresh", action="store_true", help="Optionally print refresh-token")
    parser.add_argument(
        "--verify",
        default=None,
        help="Override TLS verify: true/false or a path to CA bundle. (Overrides KEYCLOAK_VERIFY)",
    )

    args = parser.parse_args()
    cfg = load_config(args.env_file)
    cfg = prompt_for_config(cfg)


    # Precedence: CLI > .env > defaults
    keycloak_url = args.keycloak_url or cfg["keycloak_url"]
    base_path = args.base_path or cfg["base_path"]
    realm = args.realm or cfg["realm"]

    client_id = cfg["client_id"]
    client_secret = cfg["client_secret"]
    username = cfg["username"]
    password = cfg["password"]

    verify = _parse_verify(args.verify) if args.verify is not None else cfg["verify"]

    token_url = build_token_url(keycloak_url, base_path, realm)

    # Minimal debug (do not print secrets)
    print(f"[cfg] token_url={token_url}", file=sys.stderr)
    print(f"[cfg] client_id={client_id} username={username} realm={realm} verify={verify}", file=sys.stderr)

    token_response = get_token(
        token_url=token_url,
        client_id=client_id,
        client_secret=client_secret,
        username=username,
        password=password,
        verify=verify,
    )

    access_token = token_response.get("access_token")
    if not access_token:
        console.print("[err] No access_token in response. Full response:")
        console.print(JSON(json.dumps(token_response, indent=2, ensure_ascii=False)))
        return 2

    print()
    print("=== access_token ===")
    print(access_token)
    print()

    header, payload = decode_jwt_no_verify(access_token)

    print("=== JWT header ===")
    console.print(JSON(json.dumps(header, ensure_ascii=False)))
    print()

    print("=== JWT payload ===")
    console.print(JSON(json.dumps(payload, ensure_ascii=False)))
    print()

    # Optional: show refresh_token raw (if present)
    if args.refresh:
        refresh_token = token_response.get("refresh_token")
        if refresh_token:
            print("=== refresh_token ===")
            print(refresh_token)
            print()

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        console.print_exception(show_locals=True)
        raise SystemExit(1)