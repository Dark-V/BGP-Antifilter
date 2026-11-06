"""Domain suffixes, subdomain wildcards, and bounded regular expressions."""
from functools import lru_cache
import re
import time

import regex


DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
MAX_REGEX_LENGTH = 1024
REGEX_MATCH_TIMEOUT = 0.005


def domain_key(value):
    return str(value).rstrip(".").encode("idna").decode("ascii").lower()


def normalize_domain_name(value):
    domain = str(value or "").strip().rstrip(".").lower()
    if not domain or any(char.isspace() for char in domain):
        return None
    if "://" in domain or "/" in domain or ":" in domain or domain.startswith("."):
        return None
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(domain) > 253 or any(not DOMAIN_LABEL_RE.fullmatch(label) for label in domain.split(".")):
        return None
    return domain


@lru_cache(maxsize=256)
def compile_regex(pattern):
    if not pattern or len(pattern) > MAX_REGEX_LENGTH:
        raise ValueError(f"regex must contain 1 to {MAX_REGEX_LENGTH} characters")
    try:
        return regex.compile(pattern, regex.IGNORECASE | regex.VERSION1)
    except (regex.error, RecursionError) as exc:
        raise ValueError(f"invalid regex: {exc}") from exc


def normalize_rule(value):
    value = str(value).strip()
    if value.lower().startswith("regex:"):
        pattern = value[6:]
        compile_regex(pattern)
        return "regex:" + pattern
    wildcard = value.startswith("*.")
    domain = normalize_domain_name(value[2:] if wildcard else value)
    if domain is None:
        raise ValueError("expected a domain, *.domain, or regex:expression")
    return ("*." if wildcard else "") + domain


def is_pattern(value):
    return value.startswith(("regex:", "*."))


def validate_rule_list(content):
    for number, line in enumerate(content.splitlines(), 1):
        value = line.strip()
        if value and not value.startswith("#"):
            try:
                normalize_rule(value)
            except ValueError as exc:
                raise ValueError(f"Line {number}: {exc}") from exc


class DomainRules:
    def __init__(self, entries=()):
        roots, wildcards, patterns = set(), set(), []
        for entry in dict.fromkeys(normalize_rule(value) for value in entries):
            if entry.startswith("regex:"):
                patterns.append(compile_regex(entry[6:]))
            elif entry.startswith("*."):
                wildcards.add(entry[2:])
            else:
                roots.add(entry)
        self.roots, self.wildcards = roots, wildcards
        self.patterns = tuple(patterns)
        # Each policy owns its cache; a replacement cannot reuse old matches.
        self.matches = lru_cache(maxsize=4096)(self._matches)

    def _matches(self, domain):
        domain = domain_key(domain)
        labels = domain.split(".")
        for index in range(len(labels)):
            suffix = ".".join(labels[index:])
            if suffix in self.roots or (index > 0 and suffix in self.wildcards):
                return True
        deadline = time.monotonic() + REGEX_MATCH_TIMEOUT
        for pattern in self.patterns:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Domain regex matching exceeded 5 ms")
            # Do not treat a timed-out exclusion as a negative match.
            if pattern.search(domain, timeout=remaining):
                return True
        return False


def match_domain(domain, rules):
    if not isinstance(rules, DomainRules):
        rules = DomainRules(rules)
    return rules.matches(domain)
