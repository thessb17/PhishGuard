#!/usr/bin/env python3
"""Build the labelled URL dataset used to train the PhishGuard classifier.

Primary source (public, citable)
--------------------------------
PhiUSIIL Phishing URL Dataset - UCI Machine Learning Repository (ID 967),
Prasad & Chandra, 2024. 235,795 labelled URLs, licence CC BY 4.0.
https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

The upstream file labels 1 = legitimate and 0 = phishing.  PhishGuard
normalises this to ``label`` where **1 = phishing, 0 = legitimate**.

Confound balancing (important)
------------------------------
The raw corpus contains a hard label leak: **100% of its legitimate URLs are
``https://www.`` prefixed**, while only ~49% of phishing URLs use HTTPS and
~41% use ``www.``.  A classifier trained on the raw file reaches ~99.7%
accuracy simply by learning "http => phishing" - a rule that is wrong, that
contradicts the project's own security guidance (HTTPS never proves safety)
and that collapses on live traffic.

``build_dataset.py`` therefore rewrites the scheme/``www.`` prefix of a
deterministic random subset of URLs **in both classes** so that both classes
converge on the same target distribution (default 60% HTTPS, 45% ``www.``).
Only these two non-causal surface attributes are touched; hostnames, paths and
query strings are never modified. The result is a dataset where the model has
to learn real structural signals.

Augmentation (why it exists)
----------------------------
In PhiUSIIL the legitimate class is also dominated by bare root-domain URLs
(``https://www.example.org``) while phishing samples carry deep paths and
query strings.  A model trained on that alone learns "long path => phishing",
which is wrong and breaks on real corporate URLs.  ``build_dataset.py``
therefore adds a deterministic, clearly-labelled augmentation corpus of
(a) benign deep-path/query URLs and (b) phishing-style URLs on throwaway
infrastructure, so the classifier has to use real signals.

Usage
-----
    python scripts/build_dataset.py                    # download + build
    python scripts/build_dataset.py --offline          # augmentation corpus only
    python scripts/build_dataset.py --per-class 9000   # bigger sample
    python scripts/build_dataset.py --no-balance       # keep the raw confound
"""

from __future__ import annotations

import argparse
import csv
import io
import random
import sys
import urllib.request
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT = BASE_DIR / "data" / "datasets" / "url_dataset.csv"
CACHE = BASE_DIR / "data" / "datasets" / ".cache"
UCI_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
MEMBER = "PhiUSIIL_Phishing_URL_Dataset.csv"

# --------------------------------------------------------------------------
# Deterministic augmentation corpus
# --------------------------------------------------------------------------

BENIGN_HOSTS = [
    ("docs.python.org", "https"), ("developer.mozilla.org", "https"),
    ("en.wikipedia.org", "https"), ("github.com", "https"),
    ("stackoverflow.com", "https"), ("www.nist.gov", "https"),
    ("owasp.org", "https"), ("www.cisa.gov", "https"),
    ("learn.microsoft.com", "https"), ("cloud.google.com", "https"),
    ("aws.amazon.com", "https"), ("www.kaggle.com", "https"),
    ("scikit-learn.org", "https"), ("flask.palletsprojects.com", "https"),
    ("www.ncsc.gov.uk", "https"), ("www.sans.org", "https"),
    ("library.cybersafe.edu", "https"), ("intranet.example-corp.com", "https"),
    ("support.example-corp.com", "https"), ("portal.demo-it.example", "https"),
    ("news.ycombinator.com", "https"), ("www.bbc.co.uk", "https"),
    ("timesofindia.indiatimes.com", "https"), ("www.irctc.co.in", "https"),
    ("www.sbi.co.in", "https"), ("shop.example-corp.com", "https"),
]

BENIGN_PATHS = [
    "/3/library/json.html", "/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    "/wiki/Phishing", "/owasp/Top10/blob/master/2021/docs/A03_2021-Injection.md",
    "/questions/12345/how-to-validate-a-url-in-python",
    "/publications/detail/sp/800-63b/final", "/www-project-top-ten/",
    "/news-events/cybersecurity-advisories/aa24-109a",
    "/en-us/entra/identity/authentication/concept-mfa-howitworks",
    "/architecture/framework/security/overview", "/whitepapers/latest/aws-security-best-practices",
    "/datasets/search?q=phishing+url", "/stable/modules/ensemble.html",
    "/en/3.0.x/quickstart/", "/collection/phishing-guidance",
    "/reading-room/whitepapers/awareness/", "/catalogue/search?query=network+security&page=2",
    "/hr/policies/remote-working-2026", "/tickets/new?category=access&priority=normal",
    "/help/articles/2026/password-manager-rollout", "/item?id=39571234",
    "/news/technology-67890123", "/business/india-business/quarterly-results.html",
    "/nget/train-search?from=NDLS&to=BCT&date=2026-03-14",
    "/personal-banking/accounts/statements?period=last-90-days",
    "/products/laptops?sort=price_asc&page=3&filter=in-stock",
]

PHISH_BRANDS = ["paypal", "microsoft", "office365", "netflix", "amazon", "apple",
                "dhl", "fedex", "hsbc", "chase", "binance", "coinbase", "docusign",
                "dropbox", "linkedin", "instagram", "whatsapp", "icloud", "sbi", "hdfc"]
PHISH_WORDS = ["secure", "login", "verify", "account", "update", "confirm", "signin",
               "validation", "recovery", "support", "billing", "unlock", "alert", "webscr"]
PHISH_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "icu", "buzz",
              "rest", "cyou", "sbs", "link", "live", "online"]
PHISH_PATHS = ["/login.php", "/signin/verify.php", "/account/update", "/secure/confirm",
               "/auth/session", "/webscr/cmd", "/wp-content/upload/portal/index.html",
               "/customer/verification", "/id/recover", "/billing/refund"]
PHISH_QUERIES = ["?cmd=_account-details&session={sid}", "?id={sid}&country=us",
                 "?ref={sid}&verify=true", "?token={sid}", "?email=user%40example.com&id={sid}",
                 "?redirect=http%3A%2F%2Flogin-{brand}.{tld}%2Fauth", ""]


def _rand_id(rng: random.Random, length: int = 12) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choice(alphabet) for _ in range(length))


def generate_benign(rng: random.Random, count: int) -> list[str]:
    urls = set()
    while len(urls) < count:
        host, scheme = rng.choice(BENIGN_HOSTS)
        path = rng.choice(BENIGN_PATHS)
        suffix = ""
        if rng.random() < 0.35:
            suffix = f"?utm_source=newsletter&utm_campaign={_rand_id(rng, 6)}"
        elif rng.random() < 0.2:
            suffix = f"#section-{rng.randint(1, 12)}"
        urls.add(f"{scheme}://{host}{path}{suffix}")
    return sorted(urls)


def generate_phishing(rng: random.Random, count: int) -> list[str]:
    urls = set()
    while len(urls) < count:
        brand = rng.choice(PHISH_BRANDS)
        word = rng.choice(PHISH_WORDS)
        tld = rng.choice(PHISH_TLDS)
        sid = _rand_id(rng, rng.randint(8, 18))
        style = rng.randint(0, 5)
        if style == 0:
            host = f"{brand}-{word}.{_rand_id(rng, 6)}.{tld}"
        elif style == 1:
            host = f"{brand}.{word}-{_rand_id(rng, 5)}.{tld}"
        elif style == 2:
            host = f"{_rand_id(rng, 10)}.{tld}"
        elif style == 3:
            host = f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        elif style == 4:
            host = f"{brand}{rng.randint(0, 99)}-{word}.{tld}"
        else:
            host = f"xn--{_rand_id(rng, 8)}.{tld}"
        scheme = "https" if rng.random() < 0.55 else "http"
        path = rng.choice(PHISH_PATHS)
        query = rng.choice(PHISH_QUERIES).format(sid=sid, brand=brand, tld=tld)
        prefix = f"/{brand}" if rng.random() < 0.4 else ""
        urls.add(f"{scheme}://{host}{prefix}{path}{query}")
    return sorted(urls)


# --------------------------------------------------------------------------
# Confound balancing
# --------------------------------------------------------------------------

TARGET_HTTPS_RATE = 0.60
TARGET_WWW_RATE = 0.45


def _set_scheme(url: str, https: bool) -> str:
    if "://" not in url:
        url = "http://" + url
    scheme, _, rest = url.partition("://")
    return ("https://" if https else "http://") + rest


def _set_www(url: str, www: bool) -> str:
    scheme, sep, rest = url.partition("://")
    if not sep:
        return url
    host, slash, tail = rest.partition("/")
    has_www = host.lower().startswith("www.")
    if www and not has_www and host.count(".") <= 2:
        host = "www." + host
    elif not www and has_www:
        host = host[4:]
    return f"{scheme}://{host}{slash}{tail}"


#: Share of URLs in **each** class that should carry a path component.
TARGET_PATH_RATE = 0.70

#: Class-neutral path vocabulary.  These segments are attached to URLs from
#: *both* classes at the same rate, so the words themselves carry no label
#: information - only the presence and length of a path is being equalised.
NEUTRAL_SEGMENTS = [
    "about", "archive", "articles", "blog", "browse", "catalog", "category",
    "collection", "community", "content", "details", "docs", "download",
    "events", "faq", "features", "gallery", "guide", "help", "home", "index",
    "info", "item", "library", "list", "media", "news", "page", "photos",
    "post", "press", "products", "profile", "projects", "public", "reference",
    "release", "resources", "results", "reviews", "search", "section",
    "series", "shop", "site", "stories", "summary", "tags", "topics", "view",
]
NEUTRAL_EXTENSIONS = ["", "", "", "", ".html", ".htm", ".php", ".aspx"]
NEUTRAL_QUERY_KEYS = ["page", "q", "ref", "lang", "sort", "view", "tab", "src"]


def _has_path(url: str) -> bool:
    """True when the URL carries more than a bare '/' after the host."""
    _, _, rest = url.partition("://")
    _, slash, tail = rest.partition("/")
    return bool(slash) and tail.strip("/") != ""


def _strip_path(url: str) -> str:
    scheme, sep, rest = url.partition("://")
    if not sep:
        return url
    host, _, _ = rest.partition("/")
    return f"{scheme}://{host}"


def _synth_path(rng: random.Random) -> str:
    """Generate a mundane, class-neutral path (+ optional query)."""
    depth = rng.choices([1, 2, 3, 4], weights=[40, 33, 19, 8])[0]
    parts = [rng.choice(NEUTRAL_SEGMENTS) for _ in range(depth)]
    if rng.random() < 0.30:
        parts[-1] = f"{parts[-1]}-{_rand_id(rng, rng.randint(3, 8))}"
    path = "/" + "/".join(parts) + rng.choice(NEUTRAL_EXTENSIONS)
    if rng.random() < 0.28:
        key = rng.choice(NEUTRAL_QUERY_KEYS)
        path += f"?{key}={_rand_id(rng, rng.randint(1, 6))}"
    return path


def balance_path_depth(rows: list[tuple[str, int]], rng: random.Random,
                       path_rate: float = TARGET_PATH_RATE) -> list[tuple[str, int]]:
    """Equalise the *presence and length* of URL paths across both classes.

    This removes the single worst artefact in the PhiUSIIL corpus: its
    legitimate URLs were collected as bare registered domains
    (``https://www.uni-mainz.de``) while its phishing URLs were captured live
    with full deep paths.  85% of legitimate rows had no path at all versus
    62% of phishing rows, so ``path_length`` became the model's strongest
    feature and *any* ordinary URL with a path - github.com/pallets/flask,
    mail.google.com/mail/u/0 - was scored as phishing.

    Path *vocabulary* is genuine evidence and is never rewritten: an authentic
    ``/webscr/cmd?cmd=_account-details`` keeps its wording.  Only URLs that
    have no path receive a synthetic one, drawn from a neutral word list that
    is applied identically to both classes, and a matching share of URLs in
    both classes is stripped back to the bare host.  After this pass the two
    classes are statistically indistinguishable on path presence and depth,
    which forces the model onto signals that actually mean something.
    """
    balanced: list[tuple[str, int]] = []
    for url, label in rows:
        want_path = rng.random() < path_rate
        if want_path and not _has_path(url):
            url = url.rstrip("/") + _synth_path(rng)
        elif not want_path and _has_path(url):
            url = _strip_path(url)
        balanced.append((url, label))
    return balanced


def balance_confounds(rows: list[tuple[str, int]], rng: random.Random,
                      https_rate: float = TARGET_HTTPS_RATE,
                      www_rate: float = TARGET_WWW_RATE) -> list[tuple[str, int]]:
    """Force both classes onto the same scheme / 'www.' distribution.

    Only the transport scheme and the ``www.`` prefix are rewritten - two
    surface attributes that carry no causal information about phishing but
    which the raw corpus leaks perfectly.  Hostname, path and query are never
    altered, so every structural feature stays authentic.
    """
    balanced: list[tuple[str, int]] = []
    for url, label in rows:
        url = _set_scheme(url, rng.random() < https_rate)
        url = _set_www(url, rng.random() < www_rate)
        balanced.append((url, label))
    return balance_path_depth(balanced, rng)


# --------------------------------------------------------------------------
# UCI source
# --------------------------------------------------------------------------

def download_uci(force: bool = False) -> Path:
    CACHE.mkdir(parents=True, exist_ok=True)
    archive = CACHE / "phiusiil.zip"
    if archive.exists() and not force and archive.stat().st_size > 1_000_000:
        print(f"[cache] using {archive}")
        return archive
    print(f"[download] {UCI_URL}")
    request = urllib.request.Request(UCI_URL, headers={"User-Agent": "PhishGuard-dataset-builder/1.0"})
    with urllib.request.urlopen(request, timeout=180) as response, open(archive, "wb") as handle:
        handle.write(response.read())
    print(f"[download] saved {archive} ({archive.stat().st_size / 1e6:.1f} MB)")
    return archive


def load_uci_rows(archive: Path, per_class: int, seed: int) -> list[tuple[str, int]]:
    rng = random.Random(seed)
    phishing: list[str] = []
    legitimate: list[str] = []
    with zipfile.ZipFile(archive) as zf, zf.open(MEMBER) as raw:
        reader = csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8", errors="replace"))
        for row in reader:
            url = (row.get("URL") or "").strip()
            label_raw = (row.get("label") or "").strip()
            if not url or label_raw not in {"0", "1"}:
                continue
            # upstream: 1 = legitimate, 0 = phishing  ->  normalise to 1 = phishing
            (phishing if label_raw == "0" else legitimate).append(url)
    rng.shuffle(phishing)
    rng.shuffle(legitimate)
    print(f"[uci] {len(phishing):,} phishing / {len(legitimate):,} legitimate available")
    rows = [(u, 1) for u in phishing[:per_class]] + [(u, 0) for u in legitimate[:per_class]]
    return rows


def _confound_stats(rows: list[tuple[str, int]]) -> dict:
    phish = [u for u, y in rows if y == 1] or [""]
    legit = [u for u, y in rows if y == 0] or [""]
    def rate(items, test):
        return sum(1 for i in items if test(i)) / len(items)
    return {
        "phish_https": rate(phish, lambda u: u.lower().startswith("https")),
        "legit_https": rate(legit, lambda u: u.lower().startswith("https")),
        "phish_www": rate(phish, lambda u: "://www." in u.lower()),
        "legit_www": rate(legit, lambda u: "://www." in u.lower()),
        "phish_path": rate(phish, _has_path),
        "legit_path": rate(legit, _has_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the PhishGuard URL dataset")
    parser.add_argument("--per-class", type=int, default=7000,
                        help="URLs sampled per class from the UCI dataset (default 7000)")
    parser.add_argument("--augment", type=int, default=1200,
                        help="Synthetic URLs added per class (default 1200)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--offline", action="store_true",
                        help="Skip the download and build from the augmentation corpus only")
    parser.add_argument("--force-download", action="store_true")
    parser.add_argument("--no-balance", action="store_true",
                        help="Keep the raw scheme/www/path confounds (demonstrates the label leak; not recommended)")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()

    rng = random.Random(args.seed)
    rows: list[tuple[str, int, str]] = []

    if not args.offline:
        try:
            archive = download_uci(force=args.force_download)
            uci_rows = load_uci_rows(archive, args.per_class, args.seed)
            if args.no_balance:
                rows += [(u, y, "phiusiil-uci-raw") for u, y in uci_rows]
            else:
                before = _confound_stats(uci_rows)
                uci_rows = balance_confounds(uci_rows, rng)
                after = _confound_stats(uci_rows)
                print(f"[balance] https rate  phishing {before['phish_https']:.0%} -> {after['phish_https']:.0%} | "
                      f"legit {before['legit_https']:.0%} -> {after['legit_https']:.0%}")
                print(f"[balance] www   rate  phishing {before['phish_www']:.0%} -> {after['phish_www']:.0%} | "
                      f"legit {before['legit_www']:.0%} -> {after['legit_www']:.0%}")
                print(f"[balance] path  rate  phishing {before['phish_path']:.0%} -> {after['phish_path']:.0%} | "
                      f"legit {before['legit_path']:.0%} -> {after['legit_path']:.0%}")
                rows += [(u, y, "phiusiil-uci-balanced") for u, y in uci_rows]
        except Exception as exc:  # network unavailable -> degrade gracefully
            print(f"[warn] could not fetch the UCI dataset ({exc}); falling back to offline mode")
            args.offline = True

    augment = args.augment if not args.offline else max(args.augment, 4000)
    aug_rows = [(u, 0) for u in generate_benign(rng, augment)]
    aug_rows += [(u, 1) for u in generate_phishing(rng, augment)]
    if not args.no_balance:
        aug_rows = balance_confounds(aug_rows, rng)
    rows += [(u, label, "augmentation-benign" if label == 0 else "augmentation-phish")
             for u, label in aug_rows]

    seen: set[str] = set()
    unique: list[tuple[str, int, str]] = []
    for url, label, source in rows:
        key = url.strip().lower()
        if key in seen or len(url) > 2000:
            continue
        seen.add(key)
        unique.append((url.strip(), label, source))
    rng.shuffle(unique)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["url", "label", "source"])
        writer.writerows(unique)

    phish = sum(1 for _, label, _ in unique if label == 1)
    print(f"[done] wrote {len(unique):,} rows to {args.output}")
    print(f"       phishing={phish:,}  legitimate={len(unique) - phish:,}")
    print("       label semantics: 1 = phishing, 0 = legitimate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
