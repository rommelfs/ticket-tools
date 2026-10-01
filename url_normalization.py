"""Normalize internationalized URL hostnames without changing other components."""

from urllib.parse import urlsplit

import idna


def normalize_url_hostname(url):
    """Return a URL with its hostname encoded using IDNA 2008 / UTS #46."""
    if any(character.isspace() or ord(character) < 32 for character in url):
        raise ValueError("URL contains whitespace or control characters")
    parts = urlsplit(url)
    if not parts.netloc or not parts.hostname:
        raise ValueError("URL must include an authority and hostname")

    userinfo, separator, hostport = parts.netloc.rpartition("@")
    # urlsplit validates bracketed IP literals; IDNA only applies to DNS names.
    if hostport.startswith("["):
        return url
    hostname, colon, port = hostport.partition(":")
    ascii_hostname = idna.encode(hostname, uts46=True).decode("ascii")
    netloc = userinfo + separator + ascii_hostname + colon + port

    # Replace only the authority, retaining even empty '?' / '#' delimiters.
    start = url.index("//") + 2
    return url[:start] + netloc + url[start + len(parts.netloc) :]
