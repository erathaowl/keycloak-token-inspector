#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

import requests
from environs import Env
from rich.console import Console

requests.packages.urllib3.disable_warnings()
console = Console()

@dataclass(frozen=True)
class KeycloakConfig:
    base_url: str
    realm: str
    client_id: str
    client_secret: str
    verify_tls: bool
    timeout_s: int


def load_config() -> KeycloakConfig:
    env = Env()
    env.read_env()  # carica .env se presente
    return KeycloakConfig(
        base_url=env.str("KEYCLOAK_URL"),
        realm=env.str("KEYCLOAK_REALM"),
        client_id=env.str("KEYCLOAK_CLIENT_ID"),
        client_secret=env.str("KEYCLOAK_CLIENT_SECRET"),
        verify_tls=env.bool("KEYCLOAK_VERIFY_TLS", True),
        timeout_s=env.int("KEYCLOAK_TIMEOUT", 30),
    )


def _names(items: List[Dict[str, Any]]) -> Set[str]:
    return {i.get("name") for i in items if i.get("name")}


class KeycloakAdmin:
    def __init__(self, cfg: KeycloakConfig) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        self._token: Optional[str] = None

        self._group_cache: Dict[str, Dict[str, Any]] = {}

    def _url(self, path: str) -> str:
        return f"{self.cfg.base_url.rstrip('/')}{path}"

    def _raise(self, r: requests.Response) -> None:
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            raise requests.HTTPError(f"{e} | {r.text}") from None

    def _get_access_token(self) -> str:
        url = self._url(f"/realms/{self.cfg.realm}/protocol/openid-connect/token")
        data = {
            "grant_type": "client_credentials",
            "client_id": self.cfg.client_id,
            "client_secret": self.cfg.client_secret,
        }
        r = self.session.post(
            url, data=data, timeout=self.cfg.timeout_s, verify=self.cfg.verify_tls
        )
        self._raise(r)
        payload = r.json()
        return payload["access_token"]

    def _headers(self) -> Dict[str, str]:
        if not self._token:
            self._token = self._get_access_token()
        return {"Authorization": f"Bearer {self._token}"}

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        r = self.session.get(
            self._url(path),
            headers=self._headers(),
            params=params,
            timeout=self.cfg.timeout_s,
            verify=self.cfg.verify_tls,
        )
        self._raise(r)
        if r.status_code == 204:
            return None
        return r.json()

    def resolve_user_id(self, *, user_id: Optional[str], username: Optional[str]) -> str:
        if user_id:
            return user_id
        if not username:
            raise ValueError("Provide either user_id or username")

        users = self._get(
            f"/admin/realms/{self.cfg.realm}/users",
            params={"username": username, "exact": "true"},
        ) or []
        if not users:
            raise RuntimeError(f"user not found: {username}")
        if len(users) > 1:
            raise RuntimeError(
                f"multiple users found for username={username}: {[u.get('id') for u in users]}"
            )
        return users[0]["id"]

    def user_role_mappings(self, user_id: str) -> Dict[str, Any]:
        return self._get(
            f"/admin/realms/{self.cfg.realm}/users/{user_id}/role-mappings"
        ) or {}

    def group_role_mappings(self, group_id: str) -> Dict[str, Any]:
        return self._get(
            f"/admin/realms/{self.cfg.realm}/groups/{group_id}/role-mappings"
        ) or {}

    def user_effective_realm_roles(self, user_id: str) -> List[Dict[str, Any]]:
        return self._get(
            f"/admin/realms/{self.cfg.realm}/users/{user_id}/role-mappings/realm/composite"
        ) or []

    def user_effective_client_roles(self, user_id: str, client_uuid: str) -> List[Dict[str, Any]]:
        return self._get(
            f"/admin/realms/{self.cfg.realm}/users/{user_id}/role-mappings/clients/{client_uuid}/composite"
        ) or []

    def user_groups(self, user_id: str) -> List[Dict[str, Any]]:
        return self._get(f"/admin/realms/{self.cfg.realm}/users/{user_id}/groups") or []

    def get_group(self, group_id: str) -> Dict[str, Any]:
        if group_id in self._group_cache:
            return self._group_cache[group_id]
        g = self._get(f"/admin/realms/{self.cfg.realm}/groups/{group_id}") or {}
        self._group_cache[group_id] = g
        return g

    def group_effective_realm_roles(self, group_id: str) -> List[Dict[str, Any]]:
        return self._get(
            f"/admin/realms/{self.cfg.realm}/groups/{group_id}/role-mappings/realm/composite"
        ) or []

    def group_effective_client_roles(self, group_id: str, client_uuid: str) -> List[Dict[str, Any]]:
        return self._get(
            f"/admin/realms/{self.cfg.realm}/groups/{group_id}/role-mappings/clients/{client_uuid}/composite"
        ) or []

    def group_ancestors_inclusive(self, group_id: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        current_id: Optional[str] = group_id
        while current_id:
            if current_id in seen:
                break
            seen.add(current_id)
            g = self.get_group(current_id)
            out.append(g)
            current_id = g.get("parentId")
        return out

    def get_all_effective_roles_with_group_hierarchy(
        self,
        user_id: str,
        *,
        include_groups: bool = True,
    ) -> Dict[str, Any]:
        realm_roles: Set[str] = set()
        client_roles: Dict[str, Set[str]] = {}

        realm_roles |= _names(self.user_effective_realm_roles(user_id))

        user_m = self.user_role_mappings(user_id)
        user_client_mappings = user_m.get("clientMappings") or {}
        for client_id_human, cm in user_client_mappings.items():
            client_uuid = cm.get("id")
            if not client_uuid:
                continue
            roles = _names(self.user_effective_client_roles(user_id, client_uuid))
            if roles:
                client_roles.setdefault(str(client_id_human), set()).update(roles)

        groups_debug: List[Dict[str, Any]] = []
        visited_group_ids: Set[str] = set()

        if include_groups:
            direct_groups = self.user_groups(user_id)

            all_group_reprs: List[Dict[str, Any]] = []
            for g in direct_groups:
                gid = g.get("id")
                if not gid:
                    continue
                all_group_reprs.extend(self.group_ancestors_inclusive(gid))

            unique_groups: List[Dict[str, Any]] = []
            for g in all_group_reprs:
                gid = g.get("id")
                if not gid or gid in visited_group_ids:
                    continue
                visited_group_ids.add(gid)
                unique_groups.append(g)

            for g in unique_groups:
                gid = g.get("id")
                if not gid:
                    continue

                groups_debug.append(
                    {"id": gid, "path": g.get("path"), "name": g.get("name"), "parentId": g.get("parentId")}
                )

                realm_roles |= _names(self.group_effective_realm_roles(gid))

                gm = self.group_role_mappings(gid)
                group_client_mappings = gm.get("clientMappings") or {}
                for client_id_human, cm in group_client_mappings.items():
                    client_uuid = cm.get("id")
                    if not client_uuid:
                        continue
                    roles = _names(self.group_effective_client_roles(gid, client_uuid))
                    if roles:
                        client_roles.setdefault(str(client_id_human), set()).update(roles)

        return {
            "user_id": user_id,
            "include_groups": include_groups,
            "effective_realm_roles": sorted(realm_roles),
            "effective_client_roles": {cid: sorted(rs) for cid, rs in sorted(client_roles.items(), key=lambda x: x[0])},
            "debug": {
                "user_clientMappings_keys": sorted(list(user_client_mappings.keys())),
                "groups_closure_count": len(visited_group_ids),
                "groups_closure": groups_debug,
            },
        }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Get ALL effective roles for a user (composite), including group + parent-group inheritance."
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--user-id")
    g.add_argument("--username")
    p.add_argument("--no-groups", action="store_true", help="Do not include group-derived roles")
    p.add_argument("--json", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    cfg = load_config()
    kc = KeycloakAdmin(cfg)

    uid = kc.resolve_user_id(user_id=args.user_id, username=args.username)
    report = kc.get_all_effective_roles_with_group_hierarchy(uid, include_groups=not args.no_groups)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print(f"user_id: {report['user_id']}")
    print(f"include_groups: {report['include_groups']}")

    print("\neffective_client_roles:")
    if report["effective_client_roles"]:
        for client, roles in report["effective_client_roles"].items():
            print(f"  {client}:")
            for r in roles:
                print(f"    - {r}")
    else:
        print("  (none)")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        console.print_exception(show_locals=True)
        raise SystemExit(1)
