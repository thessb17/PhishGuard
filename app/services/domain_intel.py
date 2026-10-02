"""Domain intelligence: a pluggable, offline-first reputation layer.

PhishGuard deliberately has **no live threat feed**. Everything here is local
and file-backed, for three reasons:

1. The platform must work with no internet access.
2. A paid API would make the project unreproducible for anyone evaluating it.
3. A stale blocklist shipped in a git repository is worse than no blocklist,
   because it looks authoritative while being months out of date.

The interface is what matters. ``DomainIntelProvider`` defines the contract;
``LocalDomainIntelProvider`` is the offline implementation that ships. A real
deployment can add a provider backed by an internal feed without touching the
analyzers, because they depend on the interface, not the implementation.

The central design rule::

    UNKNOWN IS NOT MALICIOUS.

Almost every domain on the internet is unknown to a local list. Treating
"absent from my allowlist" as evidence of badness is the single fastest way to
build a detector that cries wolf. ``UNKNOWN`` therefore contributes **zero**
to the risk score; only ``KNOWN_SUSPICIOUS`` adds, and only ``KNOWN_SAFE``
subtracts.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


class DomainVerdict:
    """Reputation verdict for a registrable domain."""

    KNOWN_SAFE = "KNOWN_SAFE"
    KNOWN_SUSPICIOUS = "KNOWN_SUSPICIOUS"
    UNKNOWN = "UNKNOWN"

    ALL = (KNOWN_SAFE, KNOWN_SUSPICIOUS, UNKNOWN)

    #: Score adjustment contributed by the verdict itself.  UNKNOWN is zero on
    #: purpose - see the module docstring.
    WEIGHTS = {
        KNOWN_SAFE: -12.0,
        KNOWN_SUSPICIOUS: +40.0,
        UNKNOWN: 0.0,
    }

    LABELS = {
        KNOWN_SAFE: "Known safe",
        KNOWN_SUSPICIOUS: "Known suspicious",
        UNKNOWN: "Not in any local list",
    }


@dataclass(frozen=True)
class DomainIntel:
    """What the intelligence layer knows about one registrable domain."""

    domain: str
    verdict: str = DomainVerdict.UNKNOWN
    reasons: tuple[str, ...] = ()
    #: Weak signals that do not by themselves establish a verdict.
    is_shortener: bool = False
    is_suspicious_tld: bool = False
    tld: str = ""
    source: str = "local"

    @property
    def score_adjustment(self) -> float:
        return DomainVerdict.WEIGHTS.get(self.verdict, 0.0)

    @property
    def label(self) -> str:
        return DomainVerdict.LABELS.get(self.verdict, self.verdict)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "verdict": self.verdict,
            "label": self.label,
            "reasons": list(self.reasons),
            "is_shortener": self.is_shortener,
            "is_suspicious_tld": self.is_suspicious_tld,
            "tld": self.tld,
            "source": self.source,
            "score_adjustment": self.score_adjustment,
        }


# ---------------------------------------------------------------------------
# Provider interface
# ---------------------------------------------------------------------------


class DomainIntelProvider(ABC):
    """Contract for a domain reputation source.

    Implementations must be side-effect free and must never perform network
    I/O during ``lookup`` unless the deployment has explicitly opted in - the
    analyzers call this on every request, and a blocking lookup would both
    slow analysis and create an SSRF surface.
    """

    name: str = "abstract"

    @abstractmethod
    def lookup(self, domain: str) -> DomainIntel:
        """Return what is known about ``domain`` (never raises)."""

    @abstractmethod
    def brands(self) -> list["Brand"]:
        """Return the brand dictionary used for impersonation detection."""


# ---------------------------------------------------------------------------
# Brand records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Brand:
    label: str
    domains: tuple[str, ...]
    category: str = "other"

    def owns(self, domain: str) -> bool:
        """True if ``domain`` is (or is a subdomain of) a legitimate domain."""
        d = (domain or "").lower().strip(".")
        return any(d == owned or d.endswith("." + owned) for owned in self.domains)


# ---------------------------------------------------------------------------
# Local, file-backed implementation
# ---------------------------------------------------------------------------

_COMMENT_RE = re.compile(r"^\s*(#|$)")


def _read_list(path: Path) -> set[str]:
    """Read a newline-delimited list file, ignoring comments and blanks."""
    if not path.exists():
        return set()
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if _COMMENT_RE.match(line):
            continue
        out.add(line.strip().lower())
    return {v for v in out if v}


class LocalDomainIntelProvider(DomainIntelProvider):
    """Offline provider backed by plain text / JSON files in ``data/intel``.

    Files are read once and cached. They are plain text so an operator can
    edit them without touching Python, and so a diff of the repository shows
    exactly what the detector believes.
    """

    name = "local"

    def __init__(self, base_dir: Path | str | None = None):
        self.base_dir = Path(base_dir) if base_dir else _default_intel_dir()
        self._allow = _read_list(self.base_dir / "allowlist.txt")
        self._deny = _read_list(self.base_dir / "denylist.txt")
        self._tlds = _read_list(self.base_dir / "suspicious_tlds.txt")
        self._shorteners = _read_list(self.base_dir / "shorteners.txt")
        self._brands = self._load_brands(self.base_dir / "brands.json")

    # -- loading ----------------------------------------------------------
    @staticmethod
    def _load_brands(path: Path) -> list[Brand]:
        if not path.exists():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        out = []
        for entry in payload.get("brands", []):
            label = str(entry.get("label", "")).lower().strip()
            domains = tuple(str(d).lower().strip() for d in entry.get("domains", []) if d)
            if label and domains:
                out.append(Brand(label=label, domains=domains,
                                 category=str(entry.get("category", "other"))))
        return out

    # -- interface --------------------------------------------------------
    def lookup(self, domain: str) -> DomainIntel:
        d = (domain or "").lower().strip().strip(".")
        if not d:
            return DomainIntel(domain="", verdict=DomainVerdict.UNKNOWN,
                               reasons=("no hostname to evaluate",))

        tld = d.rsplit(".", 1)[-1] if "." in d else ""
        is_short = d in self._shorteners
        is_bad_tld = tld in self._tlds
        reasons: list[str] = []

        # Denylist wins over allowlist: an explicit "this is bad" is a
        # stronger statement than an inherited "this was fine".
        if self._matches(d, self._deny):
            reasons.append("listed on the local denylist")
            return DomainIntel(d, DomainVerdict.KNOWN_SUSPICIOUS, tuple(reasons),
                               is_short, is_bad_tld, tld, self.name)

        if self._matches(d, self._allow):
            reasons.append("listed on the local allowlist")
            return DomainIntel(d, DomainVerdict.KNOWN_SAFE, tuple(reasons),
                               is_short, is_bad_tld, tld, self.name)

        # Everything else is UNKNOWN. The weak signals travel with the record
        # but do NOT change the verdict.
        if is_short:
            reasons.append("known URL shortener - true destination is hidden")
        if is_bad_tld:
            reasons.append(f"'.{tld}' is over-represented in abuse reporting")
        if not reasons:
            reasons.append("not present in any local list")
        return DomainIntel(d, DomainVerdict.UNKNOWN, tuple(reasons),
                           is_short, is_bad_tld, tld, self.name)

    def brands(self) -> list[Brand]:
        return list(self._brands)

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _matches(domain: str, listed: set[str]) -> bool:
        """Exact match, or a subdomain of a listed domain."""
        if domain in listed:
            return True
        return any(domain.endswith("." + entry) for entry in listed)

    # -- introspection, used by the UI and tests --------------------------
    def stats(self) -> dict:
        return {
            "provider": self.name,
            "base_dir": str(self.base_dir),
            "allowlist": len(self._allow),
            "denylist": len(self._deny),
            "suspicious_tlds": len(self._tlds),
            "shorteners": len(self._shorteners),
            "brands": len(self._brands),
        }


def _default_intel_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "intel"


@lru_cache(maxsize=1)
def get_provider() -> DomainIntelProvider:
    """Process-wide provider.

    Cached because the files never change at runtime and every URL analysis
    needs it; re-reading five files per request would be pure waste.
    """
    return LocalDomainIntelProvider()


def reset_provider_cache() -> None:
    """Drop the cached provider (used by tests that write custom list files)."""
    get_provider.cache_clear()
