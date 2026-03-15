"""
Utility for deduplicating assets and findings.
Follows 'anew' logic to keep output unique.
"""
from typing import List, Dict, Any, Set
import hashlib

class Deduplicator:
    @staticmethod
    def deduplicate_subdomains(subdomains: List[str]) -> List[str]:
        """Normalize and deduplicate a list of subdomains."""
        unique = set()
        for sub in subdomains:
            normalized = sub.strip().lower().lstrip("*.")
            if normalized:
                unique.add(normalized)
        return sorted(list(unique))

    @staticmethod
    def deduplicate_assets(assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate assets based on their URL."""
        seen_urls = set()
        unique_assets = []
        for asset in assets:
            url = asset.get("url", "").rstrip("/")
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_assets.append(asset)
        return unique_assets

    @staticmethod
    def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate findings based on a hash of their core attributes."""
        seen_hashes = set()
        unique_findings = []
        for finding in findings:
            # Create a unique fingerprint for the finding
            fingerprint = f"{finding.get('type')}|{finding.get('url')}|{finding.get('parameter', '')}|{finding.get('evidence', '')}"
            finding_hash = hashlib.md5(fingerprint.encode()).hexdigest()
            
            if finding_hash not in seen_hashes:
                seen_hashes.add(finding_hash)
                unique_findings.append(finding)
        return unique_findings
