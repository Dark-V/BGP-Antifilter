"""Domain suffixes, subdomain wildcards, and bounded regular expressions."""
from functools import lru_cache
import re
import time

import dns.name
import regex


DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
MAX_REGEX_LENGTH = 1024
REGEX_MATCH_TIMEOUT = 0.005


def domain_key(value):
    domain = str(value)
    if domain.endswith("."):
        prefix = domain[:-1]
        preceding_escapes = len(prefix) - len(prefix.rstrip("\\"))
        if preceding_escapes % 2 == 0:
            domain = prefix
    # dnspython renders binary DNS labels as ASCII escapes. They already
    # represent valid wire labels, whose expanded text can exceed 63 bytes.
    # IDNA is only needed for Unicode names supplied by users.
    return (domain if domain.isascii() else domain.encode("idna").decode("ascii")).lower()


def normalize_domain_name(value, *, allow_wildcards=False):
    domain = str(value or "").strip().rstrip(".").lower()
    if not domain or any(char.isspace() for char in domain):
        return None
    if "://" in domain or "/" in domain or ":" in domain or domain.startswith("."):
        return None
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = domain.split(".")
    if len(domain) > 253 or any(
        not (allow_wildcards and label == "*") and not DOMAIN_LABEL_RE.fullmatch(label)
        for label in labels
    ):
        return None
    if all(label == "*" for label in labels):
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
    domain = normalize_domain_name(value[2:] if wildcard else value, allow_wildcards=True)
    if domain is None:
        raise ValueError("expected a domain, a domain mask with complete * labels, or regex:expression")
    return ("*." if wildcard else "") + domain


def is_pattern(value):
    return value.startswith("regex:") or "*" in value


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
        label_patterns = {}
        for entry in dict.fromkeys(normalize_rule(value) for value in entries):
            if entry.startswith("regex:"):
                patterns.append((entry, compile_regex(entry[6:])))
            elif entry.startswith("*.") and "*" not in entry[2:]:
                wildcards.add(entry[2:])
            elif "*" in entry:
                labels = tuple(None if label == "*" else label.encode("ascii") for label in entry.split("."))
                label_patterns.setdefault(len(labels), []).append((entry, labels))
            else:
                roots.add(entry)
        self.roots, self.wildcards = roots, wildcards
        self.patterns = tuple(patterns)
        self.label_patterns = {size: tuple(entries) for size, entries in label_patterns.items()}
        # Each policy owns its cache; a replacement cannot reuse old matches.
        self.matching_rule = lru_cache(maxsize=4096)(self._matching_rule)

    def matches(self, domain):
        return self.matching_rule(domain) is not None

    def _matching_rule(self, domain):
        domain = domain_key(domain)
        if "\\" in domain:
            # An escaped dot belongs to its label, not to the suffix boundary.
            name = dns.name.from_text(domain)
            domain_labels = tuple(label.lower() for label in name.labels[:-1])
            suffixes = [dns.name.Name(name.labels[index:]).to_text(omit_final_dot=True)
                        for index in range(len(name.labels) - 1)]
        else:
            labels = domain.split(".")
            domain_labels = tuple(label.encode("ascii") for label in labels) if self.label_patterns else ()
            suffixes = [".".join(labels[index:]) for index in range(len(labels))]
        for index, suffix in enumerate(suffixes):
            if suffix in self.roots:
                return suffix
            if index > 0 and suffix in self.wildcards:
                return f"*.{suffix}"
        # Match whole wire labels: an escaped dot inside a label is not a separator.
        for rule, labels in self.label_patterns.get(len(domain_labels), ()):
            if all(actual and (expected is None or actual == expected)
                   for actual, expected in zip(domain_labels, labels)):
                return rule
        deadline = time.monotonic() + REGEX_MATCH_TIMEOUT
        for rule, pattern in self.patterns:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Domain regex matching exceeded 5 ms")
            # Do not treat a timed-out exclusion as a negative match.
            if pattern.search(domain, timeout=remaining):
                return rule
        return None


def match_domain(domain, rules):
    if not isinstance(rules, DomainRules):
        rules = DomainRules(rules)
    return rules.matches(domain)
