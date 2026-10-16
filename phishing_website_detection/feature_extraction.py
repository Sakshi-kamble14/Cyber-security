"""
feature_extraction.py
---------------------
URL feature extraction used by BOTH train_model.py and app.py.

Keeping one shared function guarantees that the model sees exactly the same
kind of features when it is trained and when it makes a prediction.

IMPORTANT: These features are only *indicators*. A long URL or a hyphen does
not prove a site is malicious, and a clean-looking URL does not prove a site is
safe. The code never visits the URL - it only looks at the text.
"""

import ipaddress
from urllib.parse import urlparse

import pandas as pd

# The order of this list is the order of the columns given to the model.
FEATURE_NAMES = [
    "url_length",
    "num_dots",
    "num_hyphens",
    "has_ip_address",
    "has_at_symbol",
    "uses_https",
]


def _get_hostname(url: str) -> str:
    """Return the hostname of a URL (adds http:// if no scheme was typed)."""
    to_parse = url if "://" in url else "http://" + url
    try:
        return urlparse(to_parse).hostname or ""
    except ValueError:
        return ""


def _is_ip_address(hostname: str) -> bool:
    """True if the hostname is an IPv4/IPv6 address such as 192.168.0.1."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_features(url: str) -> dict:
    """Turn one URL string into a dictionary of 6 simple numeric features."""
    url = str(url).strip()
    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "has_ip_address": int(_is_ip_address(_get_hostname(url))),
        "has_at_symbol": int("@" in url),
        "uses_https": int(url.lower().startswith("https://")),
    }


def features_to_dataframe(urls) -> pd.DataFrame:
    """Build a DataFrame (one row per URL) with columns in FEATURE_NAMES order."""
    rows = [extract_features(u) for u in urls]
    return pd.DataFrame(rows, columns=FEATURE_NAMES)


def describe_indicators(features: dict) -> list:
    """Plain-English notes about what the features show (indicators only, not proof)."""
    notes = []
    if features["url_length"] > 75:
        notes.append(f"The URL is long ({features['url_length']} characters).")
    if features["num_dots"] > 3:
        notes.append(f"The URL has many dots ({features['num_dots']}).")
    if features["num_hyphens"] >= 2:
        notes.append(f"The URL has several hyphens ({features['num_hyphens']}).")
    if features["has_ip_address"]:
        notes.append("The hostname is an IP address instead of a domain name.")
    if features["has_at_symbol"]:
        notes.append("The URL contains an '@' symbol.")
    if not features["uses_https"]:
        notes.append("The URL does not start with https://.")
    if not notes:
        notes.append("None of the simple warning signs were found.")
    return notes


def predict_url(model, url: str):
    """Return (label, phishing_probability, features) for one URL.

    label is 1 for phishing and 0 for legitimate. The URL text is only analysed;
    the website is never opened.
    """
    features = extract_features(url)
    row = pd.DataFrame([features], columns=FEATURE_NAMES)
    label = int(model.predict(row)[0])
    phishing_prob = float(model.predict_proba(row)[0][list(model.classes_).index(1)])
    return label, phishing_prob, features
