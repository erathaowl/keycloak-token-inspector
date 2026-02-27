# Keycloak Token Inspector

A small CLI tool to:

- Request an `access_token` from Keycloak using the **Resource Owner Password Credentials Grant**
- Print the raw token
- Decode the JWT **without signature verification**
- Pretty-print header and claims in color using `rich`

Designed for debugging and development environments.

---

## Features

- `.env` configuration via `environs`
- CLI overrides for all parameters
- Optional interactive mode (rich prompts)
- TLS verification control (`true` / `false` / custom CA path)
- Colored JSON output
- Rich-formatted exception traces

---

## Requirements

- Python ≥ 3.10
- [uv](https://github.com/astral-sh/uv)

---

## Installation (using uv)

Clone the repository:

```bash
git clone https://github.com/erathaowl/keycloak-test.git
cd keycloak-test
```

Install dependencies:

```bash
uv sync
```

Run directly:

```bash
uv run python token_test.py
```

---

## Configuration

Copy the example file:

```bash
cp .env.example .env
```

Edit `.env` according to your environment.

---

## Example `.env`

```env
# --- Keycloak base ---
KEYCLOAK_URL=https://localhost:8443
KEYCLOAK_BASE_PATH=
KEYCLOAK_REALM=master

# --- Client ---
KEYCLOAK_CLIENT_ID=admin-cli
KEYCLOAK_CLIENT_SECRET=

# --- User credentials ---
KEYCLOAK_USERNAME=admin
KEYCLOAK_PASSWORD=admin

# --- TLS verification ---
# true  -> verify certificate
# false -> disable verification (dev only)
# or provide a CA bundle path
KEYCLOAK_VERIFY=false
```

---

## Usage

### Basic

```bash
uv run keycloak-token-inspector
```

### Override parameters via CLI

CLI arguments override `.env` values.

```bash
uv run keycloak-token-inspector \
  --realm myrealm \
  --username user \
  --password secret \
  --verify false
```

### Use a specific `.env` file

```bash
uv run keycloak-token-inspector --env-file /path/to/.env
```

### Interactive mode

Prompt for parameters interactively:

```bash
uv run keycloak-token-inspector --interactive
```

Defaults are pre-filled from `.env`.

---

## Legacy Keycloak (`/auth` path)

If your Keycloak exposes endpoints like:

```
https://host:8443/auth/realms/<realm>/...
```

Set:

```env
KEYCLOAK_BASE_PATH=/auth
```

---

## Output

The tool prints:

1. Raw `access_token`
2. Decoded JWT header (colored)
3. Decoded JWT payload / claims (colored)
4. Optional `refresh_token`

Exceptions are rendered using `rich` with a colored traceback.

---

## TLS Verification

`KEYCLOAK_VERIFY` accepts:

| Value           | Behavior                         |
| --------------- | -------------------------------- |
| true            | Standard TLS verification        |
| false           | Disable certificate verification |
| /path/to/ca.pem | Use custom CA bundle             |

⚠️ Disabling TLS verification is unsafe and should only be used in development.

---

## Limitations

* Uses **Password Grant** (not recommended for modern production architectures)
* JWT is decoded **without signature verification**
* Does not validate `iss`, `aud`, `exp`
* Intended for debugging and inspection only

---

## Possible Extensions

* JWKS-based signature verification
* Client credentials grant support
* Machine-readable JSON output mode
* Proxy support
* Claim filtering

---

## License

MIT

```
```
