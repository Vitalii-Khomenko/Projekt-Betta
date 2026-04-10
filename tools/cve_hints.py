"""
CVE Hint Lookup - tools/cve_hints.py
=====================================
Maps (product_name, version_string) tuples to known CVE identifiers for
display in the HTML scan report.  Used by training/tools/scanner.py when
building per-port advisory entries in the report pipeline.

Not called directly - imported by scanner.py's report generator.

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import re
from typing import Callable, TypedDict


class CveRule(TypedDict):
    product: str
    aliases: list[str]
    cpes: list[str]
    matcher: Callable[[str], bool]
    cve: str
    severity: str
    summary: str


def _version_key(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", version)
    return tuple(int(part) for part in parts[:4])


def _match_version(version: str, *, exact: tuple[int, ...] | None = None,
                   min_inclusive: tuple[int, ...] | None = None,
                   max_inclusive: tuple[int, ...] | None = None,
                   max_exclusive: tuple[int, ...] | None = None) -> bool:
    if not version:
        return False
    current = _version_key(version)
    if not current:
        return False
    if exact is not None:
        return current == exact
    if min_inclusive is not None and current < min_inclusive:
        return False
    if max_inclusive is not None and current > max_inclusive:
        return False
    if max_exclusive is not None and current >= max_exclusive:
        return False
    return True


_RULES: list[CveRule] = [
    {
        "product": "OpenSSH",
        "aliases": ["openssh", "ssh"],
        "cpes": ["cpe:/a:openbsd:openssh"],
        "matcher": lambda version: _match_version(version, max_exclusive=(7, 7)),
        "cve": "CVE-2018-15473",
        "severity": "medium",
        "summary": "Potential username enumeration in older OpenSSH releases.",
    },
    {
        "product": "Apache httpd",
        "aliases": ["apache httpd", "apache"],
        "cpes": ["cpe:/a:apache:http_server"],
        "matcher": lambda version: _match_version(version, exact=(2, 4, 49)),
        "cve": "CVE-2021-41773",
        "severity": "critical",
        "summary": "Path traversal and possible RCE in Apache httpd 2.4.49.",
    },
    {
        "product": "Apache httpd",
        "aliases": ["apache httpd", "apache"],
        "cpes": ["cpe:/a:apache:http_server"],
        "matcher": lambda version: _match_version(version, exact=(2, 4, 50)),
        "cve": "CVE-2021-42013",
        "severity": "critical",
        "summary": "Path traversal and possible RCE in Apache httpd 2.4.50.",
    },
    {
        "product": "vsftpd",
        "aliases": ["vsftpd", "ftp"],
        "cpes": ["cpe:/a:vsftpd_project:vsftpd"],
        "matcher": lambda version: _match_version(version, exact=(2, 3, 4)),
        "cve": "CVE-2011-2523",
        "severity": "critical",
        "summary": "Known backdoored vsftpd 2.3.4 release.",
    },
    {
        "product": "Microsoft IIS",
        "aliases": ["iis", "microsoft-iis"],
        "cpes": ["cpe:/a:microsoft:iis", "cpe:/a:microsoft:internet_information_server"],
        "matcher": lambda version: _match_version(version, exact=(6, 0)),
        "cve": "CVE-2017-7269",
        "severity": "high",
        "summary": "Potential WebDAV RCE exposure on IIS 6.0.",
    },
    {
        "product": "Apache Tomcat",
        "aliases": ["tomcat", "apache tomcat"],
        "cpes": ["cpe:/a:apache:tomcat"],
        "matcher": lambda version: _match_version(version, min_inclusive=(7, 0, 0), max_exclusive=(7, 0, 82)),
        "cve": "CVE-2017-12617",
        "severity": "high",
        "summary": "Potential JSP upload RCE on affected Tomcat versions with unsafe PUT handling.",
    },
]


def lookup_cve_hints(service: str = "", service_version: str = "", technology: str = "", banner: str = "", cpe: str = "") -> list[dict[str, str]]:
    text = " ".join(part for part in (service, service_version, technology, banner) if part).lower()
    version_source = service_version or technology or banner
    version_match = re.search(r"(\d+(?:\.\d+)+(?:p\d+)?)", version_source)
    version = version_match.group(1) if version_match else ""
    cpe_lower = cpe.lower().strip()

    hints: list[dict[str, str]] = []
    for rule in _RULES:
        aliases = [str(alias) for alias in rule["aliases"]]
        cpe_values = [str(value).lower() for value in rule.get("cpes", [])]
        matches_alias = any(alias in text for alias in aliases)
        matches_cpe = bool(cpe_lower and any(cpe_lower.startswith(value) or value in cpe_lower for value in cpe_values))
        if not (matches_alias or matches_cpe):
            continue
        matcher = rule["matcher"]
        if callable(matcher) and not matcher(version):
            continue
        hints.append(
            {
                "cve": str(rule["cve"]),
                "severity": str(rule["severity"]),
                "summary": str(rule["summary"]),
                "product": str(rule["product"]),
            }
        )
    return hints


def summarize_cve_hints(hints: list[dict[str, str]]) -> str:
    if not hints:
        return ""
    return " ; ".join(f"{hint['cve']} ({hint['severity']}): {hint['summary']}" for hint in hints[:2])
