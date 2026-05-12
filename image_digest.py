#!/usr/bin/env python3
"""
Resolve a container image reference to its registry manifest digest.

Output is exactly ``sha256:<64 lowercase hex>``. Uses the OCI Distribution /
Docker Registry HTTP V2 API (stdlib only).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

# Negotiate like common clients: prefer index / manifest list, then single-arch manifest.
ACCEPT_MANIFEST = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v1+json",
    )
)


@dataclass(frozen=True)
class ImageRef:
    registry: str
    repository: str
    reference: str  # tag or digest (without @)


_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$", re.IGNORECASE)
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$")


def _parse_image_ref(raw: str) -> ImageRef:
    s = raw.strip()
    if not s:
        raise ValueError("empty image reference")

    if "@" in s:
        name_part, _, ref_part = s.rpartition("@")
        ref_part = ref_part.strip()
        if not name_part or not ref_part:
            raise ValueError(f"invalid reference: {raw!r}")
        if not _DIGEST_RE.match(ref_part):
            raise ValueError(
                f"unsupported digest form (only sha256:... is supported): {ref_part!r}"
            )
        reference = ref_part.lower()
    else:
        name_part = s
        if ":" in name_part:
            # Last ':' separates tag; registry may contain ':' (port).
            idx = name_part.rfind(":")
            tag = name_part[idx + 1 :]
            if "/" not in tag and _TAG_RE.match(tag):
                name_part = name_part[:idx]
                reference = tag
            else:
                reference = "latest"
        else:
            reference = "latest"

    # Split registry / repository (simplified; covers host/repo and default docker.io).
    parts = name_part.split("/")
    first = parts[0]
    is_registry = (
        "." in first
        or ":" in first
        or first == "localhost"
        or first == "127.0.0.1"
    )
    if is_registry:
        registry = first
        repo = "/".join(parts[1:]) if len(parts) > 1 else ""
    else:
        registry = "docker.io"
        repo = "/".join(parts)

    if not repo:
        raise ValueError(f"missing repository in reference: {raw!r}")

    # docker.io short names -> library/ on Docker Hub
    if registry == "docker.io" and "/" not in repo:
        repo = "library/" + repo

    repository = repo.lower()
    return ImageRef(registry=registry, repository=repository, reference=reference)


def _registry_v2_base(registry: str) -> str:
    if registry == "docker.io":
        return "https://registry-1.docker.io/v2/"
    if registry == "registry-1.docker.io":
        return "https://registry-1.docker.io/v2/"
    scheme = "https"
    host = registry
    if host.startswith("http://"):
        scheme, _, host = host.partition("://")
        scheme = "http"
    elif host.startswith("https://"):
        scheme, _, host = host.partition("://")
        scheme = "https"
    return f"{scheme}://{host}/v2/"


def _docker_hub_token(repository: str) -> str | None:
    q = urllib.parse.urlencode(
        {
            "service": "registry.docker.io",
            "scope": f"repository:{repository}:pull",
        }
    )
    url = f"https://auth.docker.io/token?{q}"
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            f"Docker Hub token request failed: HTTP {e.code} {e.reason}"
        ) from e
    data = json.loads(body.decode())
    token = data.get("token") or data.get("access_token")
    if not token:
        return None
    return str(token)


def _request(
    method: str,
    url: str,
    headers: dict[str, str],
    *,
    bearer: str | None,
    data: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    h = dict(headers)
    if bearer:
        h["Authorization"] = f"Bearer {bearer}"
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method=method, headers=h, data=data)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
            rh = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, rh, resp.read()
    except urllib.error.HTTPError as e:
        rh = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        body = e.read() if hasattr(e, "read") else b""
        return e.code, rh, body


def _header_digest(headers: dict[str, str]) -> str | None:
    d = headers.get("docker-content-digest")
    if not d:
        return None
    d = d.strip().strip('"')
    if _DIGEST_RE.match(d):
        return d.lower()
    return None


def _digest_from_body(body: bytes) -> str:
    h = hashlib.sha256(body).hexdigest()
    return f"sha256:{h}"


def _www_authenticate_bearer_challenge(headers: dict[str, str]) -> dict[str, str] | None:
    raw = headers.get("www-authenticate")
    if not raw:
        return None
    # Www-Authenticate: Bearer realm="...",service="...",scope="..."
    m = re.match(r"^\s*Bearer\s+(.+)$", raw, re.IGNORECASE)
    if not m:
        return None
    parts: dict[str, str] = {}
    for item in re.finditer(r'(\w+)="([^"]*)"', m.group(1)):
        parts[item.group(1).lower()] = item.group(2)
    return parts


def _fetch_bearer_token(
    registry_host: str, repository: str, challenge: dict[str, str]
) -> str | None:
    realm = challenge.get("realm")
    if not realm:
        return None
    qs: dict[str, str] = {}
    if "service" in challenge:
        qs["service"] = challenge["service"]
    if "scope" in challenge:
        qs["scope"] = challenge["scope"]
    else:
        qs["scope"] = f"repository:{repository}:pull"
    url = realm
    if qs:
        sep = "&" if "?" in realm else "?"
        url = f"{realm}{sep}{urllib.parse.urlencode(qs)}"
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError:
        return None
    token = body.get("token") or body.get("access_token")
    return str(token) if token else None


def _ensure_sha256_digest(d: str) -> str:
    """Return canonical ``sha256:<64 hex>`` (lowercase) or raise."""
    t = d.strip().strip('"').lower()
    if not _DIGEST_RE.match(t):
        raise RuntimeError(f"registry digest is not sha256: form: {d!r}")
    return t


def resolve_digest(image_ref: str) -> str:
    ref = _parse_image_ref(image_ref)
    if ref.reference.startswith("sha256:"):
        return _ensure_sha256_digest(ref.reference)

    base = _registry_v2_base(ref.registry)
    path_repo = urllib.parse.quote(ref.repository, safe="")
    manifest_url = f"{base}{path_repo}/manifests/{urllib.parse.quote(ref.reference, safe=':')}"

    bearer: str | None = None
    if ref.registry in ("docker.io", "registry-1.docker.io"):
        bearer = _docker_hub_token(ref.repository)

    def do_head(b: str | None) -> tuple[int, dict[str, str], bytes]:
        return _request(
            "HEAD",
            manifest_url,
            {"Accept": ACCEPT_MANIFEST},
            bearer=b,
        )

    status, headers, _ = do_head(bearer)
    if status == 401:
        ch = _www_authenticate_bearer_challenge(headers)
        if ch:
            host = ref.registry
            if host == "docker.io":
                host = "registry-1.docker.io"
            bearer2 = _fetch_bearer_token(host, ref.repository, ch)
            if bearer2:
                bearer = bearer2
                status, headers, _ = do_head(bearer)

    if status in (200, 301, 302):
        d = _header_digest(headers)
        if d:
            return _ensure_sha256_digest(d)

    status, headers, body = _request(
        "GET",
        manifest_url,
        {"Accept": ACCEPT_MANIFEST},
        bearer=bearer,
    )
    if status == 401:
        ch = _www_authenticate_bearer_challenge(headers)
        if ch:
            host = ref.registry
            if host == "docker.io":
                host = "registry-1.docker.io"
            bearer2 = _fetch_bearer_token(host, ref.repository, ch)
            if bearer2:
                bearer = bearer2
                status, headers, body = _request(
                    "GET",
                    manifest_url,
                    {"Accept": ACCEPT_MANIFEST},
                    bearer=bearer2,
                )

    if status != 200:
        msg = body.decode(errors="replace")[:500]
        raise RuntimeError(f"registry returned HTTP {status} for manifests: {msg}")

    d = _header_digest(headers)
    if d:
        return _ensure_sha256_digest(d)
    return _ensure_sha256_digest(_digest_from_body(body))


def main() -> int:
    p = argparse.ArgumentParser(
        description="Print the registry manifest digest as sha256:<hex> for a container image reference."
    )
    p.add_argument(
        "image",
        help='Image reference, e.g. nginx:latest, docker.io/library/alpine:3.20, ghcr.io/org/image:tag',
    )
    args = p.parse_args()
    try:
        digest = resolve_digest(args.image)
    except (ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
