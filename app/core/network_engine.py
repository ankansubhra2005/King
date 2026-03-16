"""
Module: Network & Infrastructure Scanning
Handles port scanning and service detection using Nmap.
Converts raw port data into the standard finding format for risk scoring & reports.
"""
import asyncio
from typing import List, Dict, Optional
from app.core.verbose import v_found, v_info


# Ports that are considered dangerous / high-severity when exposed
DANGEROUS_PORTS = {
    "21":    ("FTP",           "high"),
    "22":    ("SSH",           "medium"),
    "23":    ("Telnet",        "high"),
    "25":    ("SMTP",          "medium"),
    "53":    ("DNS",           "medium"),
    "80":    ("HTTP",          "info"),
    "110":   ("POP3",          "medium"),
    "143":   ("IMAP",          "medium"),
    "443":   ("HTTPS",         "info"),
    "445":   ("SMB",           "high"),
    "1433":  ("MSSQL",         "high"),
    "1521":  ("Oracle DB",     "high"),
    "2375":  ("Docker API",    "critical"),
    "2376":  ("Docker TLS",    "high"),
    "3306":  ("MySQL",         "high"),
    "3389":  ("RDP",           "high"),
    "5432":  ("PostgreSQL",    "high"),
    "5900":  ("VNC",           "high"),
    "6379":  ("Redis",         "high"),
    "8080":  ("HTTP-Alt",      "medium"),
    "8443":  ("HTTPS-Alt",     "medium"),
    "9200":  ("Elasticsearch", "high"),
    "9300":  ("Elasticsearch", "high"),
    "27017": ("MongoDB",       "high"),
    "27018": ("MongoDB",       "high"),
    "11211": ("Memcached",     "high"),
}

SEVERITY_NEXT_STEP = {
    "critical": "Immediately restrict access. Exposed management API is remotely exploitable.",
    "high":     "Restrict to internal network only. Test for authentication bypass and default credentials.",
    "medium":   "Verify service is intentionally exposed. Check for version-specific CVEs.",
    "info":     "Confirm service is intentional. Keep patched.",
}


class NetworkEngine:
    """
    NetworkEngine uses Nmap to discover open ports and services on targets.
    Results are converted to the standard finding format for unified reporting.
    """

    def __init__(self, threads: int = 10):
        self.threads = threads

    # ── Public API ─────────────────────────────────────────────────────────

    async def scan_subdomains(self, subdomains: List[Dict]) -> List[Dict]:
        """
        Scan all provided subdomains with Nmap and return raw port results.
        """
        # Scan all provided hosts that have a name, regardless of is_alive state.
        # This ensures we find open ports even on hosts that block HTTP.
        alive = [s.get("fqdn", "") for s in subdomains if s.get("fqdn")]
        if not alive:
            v_info("Network", "No targets to scan")
            return []
        v_info("Network", f"Scanning {len(alive)} hosts with Nmap")
        return await self.scan_all(alive, scan_type="FAST")

    async def scan_ports(self, target: str, scan_type: str = "FAST") -> List[Dict]:
        """
        Run nmap against a single target.
        scan_type: STEALTH (-sS), AGGRESSIVE (-A), FAST (-F), SERVICE (-sV)
        """
        flags = {
            "STEALTH":    ["-sS"],
            "AGGRESSIVE": ["-A"],
            "FAST":       ["-F", "-sV"],
            "SERVICE":    ["-sV"],
        }
        nmap_flags = flags.get(scan_type, ["-F", "-sV"])
        cmd = ["nmap"] + nmap_flags + ["-T4", "-Pn", target, "-oX", "-"]

        v_info("Network", f"nmap {' '.join(nmap_flags)} {target}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                v_info("Network", f"Nmap failed on {target}: {stderr.decode()[:200]}")
                return []

            return self._parse_xml_results(stdout.decode(), target)
        except FileNotFoundError:
            v_info("Network", "nmap not found — install with: sudo apt install nmap")
            return []
        except Exception as e:
            v_info("Network", f"Error running nmap on {target}: {e}")
            return []

    async def scan_all(self, targets: List[str], scan_type: str = "FAST") -> List[Dict]:
        """Scan multiple targets sequentially (avoids overwhelming the network)."""
        all_results: List[Dict] = []
        for t in targets:
            res = await self.scan_ports(t, scan_type=scan_type)
            all_results.extend(res)
        return all_results

    def to_findings(self, port_results: List[Dict]) -> List[Dict]:
        """
        Convert raw port scan results into the standard finding format used
        by all other engines (compatible with risk scoring + report writers).
        """
        findings = []
        for p in port_results:
            port      = str(p.get("port", ""))
            target    = p.get("target", "")
            service   = p.get("service", "unknown")
            version   = p.get("version", "")
            protocol  = p.get("protocol", "tcp")

            # Determine severity from known-dangerous ports
            known = DANGEROUS_PORTS.get(port)
            if known:
                service_hint, severity = known
            else:
                service_hint = service
                severity = "info"

            evidence = f"Port {port}/{protocol} open — {service} {version}".strip()
            next_step = SEVERITY_NEXT_STEP.get(severity, SEVERITY_NEXT_STEP["info"])

            findings.append({
                "type":               "open_port",
                "subtype":            service_hint,
                "severity":           severity,
                "url":                f"{target}:{port}",
                "target":             target,
                "port":               port,
                "protocol":           protocol,
                "service":            service,
                "version":            version,
                "evidence":           evidence,
                "confidence":         0.95,
                "suggested_next_step": next_step,
            })

            v_found("port", f"{target}:{port}", f"{service} {version} [{severity.upper()}]")

        return findings

    # ── Internal ───────────────────────────────────────────────────────────

    def _parse_xml_results(self, xml_data: str, target: str) -> List[Dict]:
        """Parse Nmap XML output into structured list of port dicts."""
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(xml_data)
            results = []
            for port in root.findall(".//port"):
                state_elem = port.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue
                portid   = port.get("portid", "")
                protocol = port.get("protocol", "tcp")
                svc      = port.find("service")
                svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
                version  = svc.get("version", "")      if svc is not None else ""
                product  = svc.get("product", "")      if svc is not None else ""
                full_ver = f"{product} {version}".strip()

                results.append({
                    "target":   target,
                    "port":     portid,
                    "protocol": protocol,
                    "service":  svc_name,
                    "version":  full_ver,
                    "status":   "open",
                })
            return results
        except Exception:
            return []
