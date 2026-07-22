"""
Input validation utilities for the recon framework.

Validates domains, URLs, hostnames, and other user-supplied values
before they reach the pipeline.
"""

import re
from typing import List

from recon.exceptions import ValidationError

# RFC 952 / RFC 1123 hostname pattern
_HOSTNAME_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Generic URL pattern (scheme + host)
_URL_PATTERN = re.compile(
    r"^https?://[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"(?::\d{1,5})?(?:/[^\s]*)?$"
)

# IPv4 address pattern
_IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def validate_domain(domain: str) -> str:
    """Validate and normalize a domain name.

    Parameters
    ----------
    domain:
        The domain string to validate (e.g. ``"example.com"``).

    Returns
    -------
    str
        The validated, lowercased domain.

    Raises
    ------
    ValidationError
        If the domain is malformed.
    """
    domain = domain.strip().lower()
    if not domain:
        raise ValidationError("Domain must not be empty.")
    if not _HOSTNAME_PATTERN.match(domain):
        raise ValidationError(
            f"Invalid domain format: {domain!r}. "
            f"Expected something like 'example.com'."
        )
    return domain


def validate_url(url: str) -> str:
    """Validate a URL (http/https).

    Parameters
    ----------
    url:
        The URL string to validate.

    Returns
    -------
    str
        The validated, stripped URL.

    Raises
    ------
    ValidationError
        If the URL is malformed.
    """
    url = url.strip()
    if not url:
        raise ValidationError("URL must not be empty.")
    if not _URL_PATTERN.match(url):
        raise ValidationError(f"Invalid URL format: {url!r}.")
    return url


def validate_hostname(hostname: str) -> str:
    """Validate a hostname (domain or IP address).

    Parameters
    ----------
    hostname:
        The hostname string to validate.

    Returns
    -------
    str
        The validated, lowercased hostname.

    Raises
    ------
    ValidationError
        If the hostname is malformed.
    """
    hostname = hostname.strip().lower()
    if not hostname:
        raise ValidationError("Hostname must not be empty.")
    if _HOSTNAME_PATTERN.match(hostname) or _IPV4_PATTERN.match(hostname):
        return hostname
    raise ValidationError(f"Invalid hostname: {hostname!r}.")


def validate_subdomain_list(subdomains: List[str]) -> List[str]:
    """Validate a list of subdomains, returning only valid entries.

    Invalid entries are silently omitted.
    """
    valid: List[str] = []
    for entry in subdomains:
        entry = entry.strip().lower()
        if not entry:
            continue
        # Subdomains are hostnames relative to a parent domain
        if _HOSTNAME_PATTERN.match(entry):
            valid.append(entry)
    return valid