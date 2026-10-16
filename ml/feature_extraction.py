"""
URL feature extraction for phishing detection.

Safety: everything here is pure string parsing. No network request, DNS lookup,
redirect following, or content download is ever performed on a submitted URL.
"""
import ipaddress
import math
import re
from collections import Counter, OrderedDict
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "bl.ink",
}
SUSPICIOUS_KEYWORDS = (
    "login", "signin", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "wallet", "webscr", "suspend", "unlock", "billing",
)
SUSPICIOUS_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "country", "work"}
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}
DEFAULT_PORTS = {"http": 80, "https": 443}

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_NUMERIC_HOST_RE = re.compile(r"^(0x[0-9a-f]+|\d+)$", re.IGNORECASE)


class InvalidURLError(ValueError):
    """Raised when a submitted URL is malformed or unsupported."""


@dataclass(frozen=True)
class ParsedURL:
    original: str
    normalized: str      # scheme://host[:port]/path?query  (credentials and fragment removed)
    scheme: str
    host: str
    port: "int | None"
    path: str
    query: str
    has_userinfo: bool


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_NUMERIC_HOST_RE.match(host))  # decimal / hex encoded IPv4


def parse_url(raw) -> ParsedURL:
    """Validate and normalize a URL string. Raises InvalidURLError on bad input."""
    if not isinstance(raw, str):
        raise InvalidURLError("URL must be a string.")
    url = raw.strip()
    if not url:
        raise InvalidURLError("URL is empty.")
    if len(url) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL is longer than {MAX_URL_LENGTH} characters.")
    if re.search(r"[\s\x00-\x1f\x7f]", url):
        raise InvalidURLError("URL contains whitespace or control characters.")
    if "://" not in url:
        url = "http://" + url  # parse only; never fetched
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise InvalidURLError("URL could not be parsed.")
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise InvalidURLError("Only http and https URLs are supported.")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise InvalidURLError("URL has no hostname.")

    if not _is_ip(host):
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise InvalidURLError("Hostname is invalid.")
        labels = ascii_host.split(".")
        if len(ascii_host) > 253 or len(labels) < 2 or not all(_LABEL_RE.match(l) for l in labels):
            raise InvalidURLError("Hostname is invalid.")
        host = ascii_host

    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != DEFAULT_PORTS[scheme]:
        netloc += f":{port}"
    normalized = f"{scheme}://{netloc}{parts.path or '/'}"
    if parts.query:
        normalized += f"?{parts.query}"
    return ParsedURL(raw.strip(), normalized, scheme, host, port, parts.path, parts.query,
                     "@" in parts.netloc)


def _split_host(host: str):
    """Return (subdomain_labels, registered_domain_labels). Heuristic, no public-suffix list."""
    labels = host.split(".")
    keep = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL else 2
    return labels[:-keep], labels[-keep:]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


FEATURE_INFO = OrderedDict([
    ("url_length", ("URL length", "Phishing URLs are often long to hide the real domain.")),
    ("hostname_length", ("Hostname length", "Very long hostnames can imitate trusted names.")),
    ("path_length", ("Path length", "Long paths can bury suspicious tokens.")),
    ("query_length", ("Query length", "Long query strings can carry tracking or redirect data.")),
    ("num_dots", ("Dots in URL", "Many dots usually mean many nested subdomains.")),
    ("num_subdomains", ("Subdomain count", "Deep subdomain chains (e.g. brand.example.attacker.com) are a common trick.")),
    ("has_ip_address", ("IP address as host", "Legitimate sites rarely use a raw IP instead of a domain name.")),
    ("is_https", ("Uses HTTPS", "HTTPS only means the connection is encrypted. Phishing sites use it too, so it is NOT proof of safety.")),
    ("has_at_symbol", ("Contains '@'", "Text before '@' is ignored by browsers and can disguise the real destination.")),
    ("num_hyphens_host", ("Hyphens in hostname", "Hyphenated names (secure-login-bank.com) often imitate real brands.")),
    ("num_hyphens_url", ("Hyphens in URL", "Excessive hyphens are mildly associated with deceptive URLs.")),
    ("is_shortener", ("URL shortener", "Shorteners hide the final destination.")),
    ("num_suspicious_keywords", ("Suspicious keywords", "Words like login, verify, or update appear often in credential-theft lures.")),
    ("has_nonstandard_port", ("Unusual port", "Public sites normally use ports 80 or 443.")),
    ("num_digits", ("Digits in URL", "Random digit strings are common in generated phishing URLs.")),
    ("digit_ratio", ("Digit ratio", "A high share of digits is unusual for human-readable URLs.")),
    ("num_special_chars", ("Special characters", "Characters such as ? = & % _ are heavier in obfuscated URLs.")),
    ("path_depth", ("Path depth", "Deep folder paths can indicate hosted phishing kits.")),
    ("has_double_slash_in_path", ("'//' inside path", "May indicate an embedded redirect.")),
    ("num_query_params", ("Query parameters", "Many parameters can indicate redirect or tracking abuse.")),
    ("has_suspicious_tld", ("Risky TLD", "Some cheap or free TLDs are over-represented in abuse reports. This is a weak signal.")),
    ("has_punycode", ("Punycode (xn--)", "Can hide look-alike (homograph) characters in the domain.")),
    ("host_entropy", ("Hostname randomness", "High entropy suggests an auto-generated domain.")),
    ("has_encoded_chars", ("Percent-encoding", "Encoded characters can hide the real content of the URL.")),
])
FEATURE_NAMES = list(FEATURE_INFO.keys())


def extract_features(url) -> "OrderedDict[str, float]":
    """Return an ordered feature dict for a URL string (raises InvalidURLError if invalid)."""
    p = parse_url(url)
    full = p.normalized.lower()
    is_ip = _is_ip(p.host)
    sub, reg = ([], [p.host]) if is_ip else _split_host(p.host)
    tld = "" if is_ip else p.host.rsplit(".", 1)[-1]
    digits = sum(ch.isdigit() for ch in full)
    path_parts = [s for s in p.path.split("/") if s]

    f = OrderedDict()
    f["url_length"] = len(p.normalized)
    f["hostname_length"] = len(p.host)
    f["path_length"] = len(p.path)
    f["query_length"] = len(p.query)
    f["num_dots"] = full.count(".")
    f["num_subdomains"] = len(sub)
    f["has_ip_address"] = int(is_ip)
    f["is_https"] = int(p.scheme == "https")
    f["has_at_symbol"] = int(p.has_userinfo or "@" in p.original)
    f["num_hyphens_host"] = p.host.count("-")
    f["num_hyphens_url"] = full.count("-")
    f["is_shortener"] = int(".".join(reg) in SHORTENERS)
    f["num_suspicious_keywords"] = sum(full.count(k) for k in SUSPICIOUS_KEYWORDS)
    f["has_nonstandard_port"] = int(p.port is not None and p.port != DEFAULT_PORTS[p.scheme])
    f["num_digits"] = digits
    f["digit_ratio"] = round(digits / len(full), 4)
    f["num_special_chars"] = sum(full.count(c) for c in "?=&%_~#!$*")
    f["path_depth"] = len(path_parts)
    f["has_double_slash_in_path"] = int("//" in p.path)
    f["num_query_params"] = len([q for q in p.query.split("&") if q])
    f["has_suspicious_tld"] = int(tld in SUSPICIOUS_TLDS)
    f["has_punycode"] = int("xn--" in p.host)
    f["host_entropy"] = round(_entropy(p.host), 4)
    f["has_encoded_chars"] = int("%" in (p.path + p.query))
    return f
