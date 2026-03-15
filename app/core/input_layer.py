"""
Module 1: Input Layer
Handles target validation, scope definition, and configuration.
"""
import re
import ipaddress
from typing import List, Optional
from dataclasses import dataclass, field
import tldextract


@dataclass
class ScanConfig:
    """Controls scan behavior."""
    mode: str = "passive"          # "passive" or "active"
    rate_limit: int = 50           # requests/second
    max_depth: int = 3             # crawler depth
    threads: int = 20
    custom_headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    user_agent: str = "Mozilla/5.0 (compatible; ReconBot/1.0)"
    timeout: int = 10


class ScopeFilter:
    """
    Enforces bug bounty scope rules.
    Supports wildcards (*.example.com), specific domains, and CIDR ranges.
    """

    def __init__(self, in_scope: List[str], out_of_scope: Optional[List[str]] = None):
        self.in_scope = in_scope or []
        self.out_of_scope = out_of_scope or []
        self._in_patterns = [self._compile(s) for s in self.in_scope]
        self._out_patterns = [self._compile(s) for s in self.out_of_scope]

    def _compile(self, rule: str):
        """Convert a scope rule to a regex or CIDR network."""
        rule = rule.strip()
        # CIDR
        try:
            return ("cidr", ipaddress.ip_network(rule, strict=False))
        except ValueError:
            pass
        # Wildcard domain → regex
        # If it starts with *., match subdomains or the domain itself
        if rule.startswith("*."):
            base_domain = re.escape(rule[2:])
            return ("regex", re.compile(rf"^(?:.+\.)?{base_domain}$", re.IGNORECASE))
        # Exact domain match
        return ("regex", re.compile(rf"^{re.escape(rule)}$", re.IGNORECASE))

    def _matches(self, target: str, patterns: list) -> bool:
        for kind, pattern in patterns:
            if kind == "cidr":
                try:
                    return ipaddress.ip_address(target) in pattern
                except ValueError:
                    pass
            else:
                if pattern.match(target):
                    return True
        return False

    def is_in_scope(self, target: str) -> bool:
        """Returns True if target is in-scope and not out-of-scope."""
        if self._out_patterns and self._matches(target, self._out_patterns):
            return False
        if not self._in_patterns:
            return True  # no restrictions
        return self._matches(target, self._in_patterns)

    def filter(self, targets: List[str]) -> List[str]:
        """Filter a list, keeping only in-scope targets."""
        return [t for t in targets if self.is_in_scope(t)]


class TargetIngestion:
    """Parses and validates targets from various input formats."""

    def __init__(self, scope_filter: Optional[ScopeFilter] = None):
        self.scope = scope_filter

    def from_string(self, raw: str) -> List[str]:
        """Parse single domain, comma-separated, or newline-separated targets."""
        targets = re.split(r"[\n,\s]+", raw.strip())
        return self._validate(targets)

    def from_file(self, path: str) -> List[str]:
        """Load targets from a .txt file."""
        with open(path, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
        return self._validate(targets)

    def _validate(self, targets: List[str]) -> List[str]:
        valid = []
        for t in targets:
            t = t.lower().strip()
            # Try CIDR
            try:
                ipaddress.ip_network(t, strict=False)
                valid.append(t)
                continue
            except ValueError:
                pass
            # Try domain
            ext = tldextract.extract(t)
            if ext.domain and ext.suffix:
                valid.append(t)
        if self.scope:
            valid = self.scope.filter(valid)
        return list(set(valid))


def get_root_domain(url: str) -> str:
    """Extract root domain from URL or FQDN."""
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"
