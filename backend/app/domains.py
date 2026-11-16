"""Domain identity using IDNA and an explicitly offline, pinned PSL snapshot."""

import hashlib
import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files

import idna
import tldextract

PSL_SNAPSHOT_SHA256 = "b69315c085d53972724b8f2df111ffc329b0c84fe0a47d62c8c91655cc774a38"


@dataclass(frozen=True)
class Domain:
    host: str
    registrable: str | None
    suffix: str | None
    is_ip: bool = False
    is_private_suffix: bool = False


@lru_cache(maxsize=1)
def _offline_extractor() -> tldextract.TLDExtract:
    snapshot = files("tldextract").joinpath(".tld_set_snapshot").read_bytes()
    if hashlib.sha256(snapshot).hexdigest() != PSL_SNAPSHOT_SHA256:
        raise RuntimeError("PSL snapshot differs from the reviewed dependency pin")
    return tldextract.TLDExtract(
        cache_dir=None,
        suffix_list_urls=(),
        fallback_to_snapshot=True,
        include_psl_private_domains=True,
    )


def normalize_domain(value: str) -> Domain:
    if not value or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Invalid domain")
    # Scoped IPv6 literals and URL escape sequences are not DNS names.
    if "%" in value or any(c in value for c in "/\\@?#"):
        raise ValueError("Invalid domain")
    value = value.removesuffix(".")
    try:
        ip = ipaddress.ip_address(value)
        return Domain(host=ip.compressed, registrable=None, suffix=None, is_ip=True)
    except ValueError:
        pass
    try:
        host = idna.encode(value, uts46=True, std3_rules=True).decode("ascii").lower()
        host = host.removesuffix(".")
    except idna.IDNAError as error:
        raise ValueError("Invalid domain") from error
    if len(host) > 253:
        raise ValueError("Invalid domain")
    try:
        ip = ipaddress.ip_address(host)
        return Domain(host=ip.compressed, registrable=None, suffix=None, is_ip=True)
    except ValueError:
        pass
    parts = _offline_extractor()(host)
    return Domain(
        host=host,
        registrable=parts.top_domain_under_public_suffix or None,
        suffix=parts.suffix or None,
        is_private_suffix=parts.is_private,
    )
