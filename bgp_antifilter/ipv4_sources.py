"""Extract IPv4 candidates from plain, rule-list, and JSON source fragments."""

import re


# Keep the whole numeric mask, including invalid lengths, for ipaddress to
# validate. Never backtrack from a malformed CIDR to its bare address as /32.
_IPV4_TOKEN = re.compile(
    r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}"
    r"(?:\\?/[+-]?\d+)?(?![\d.]|\\?/[+-]?\d)"
)


def extract_ipv4_candidates(text):
    # JSON may escape the slash in CIDRs. Decode only the matched token; source
    # files may concatenate multiple JSON documents and non-JSON rule lists.
    return (match.group().replace("\\/", "/", 1) for match in _IPV4_TOKEN.finditer(text))
