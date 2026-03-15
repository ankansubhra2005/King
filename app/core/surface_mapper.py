"""
Phase 2: Attack Surface Mapper.
Generates a JSON graph visualization of the target infrastructure.
"""
from typing import List, Dict, Any

class AttackSurfaceMapper:
    @staticmethod
    def generate_graph(domain: str, subdomains: List[Dict[str, Any]], assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a nodes-and-edges graph for visualization."""
        nodes = []
        edges = []

        # Root node
        nodes.append({"id": domain, "label": domain, "type": "root", "risk": "low"})

        # Subdomain nodes
        for sub in subdomains:
            fqdn = sub.get("fqdn")
            if not fqdn: continue
            
            nodes.append({
                "id": fqdn,
                "label": fqdn,
                "type": "subdomain",
                "risk": "medium" if sub.get("is_alive") else "low",
                "ip": sub.get("ip_address"),
                "waf": sub.get("waf_detected")
            })
            edges.append({"from": domain, "to": fqdn, "label": "has_subdomain"})

            # Port nodes if enriched
            for port in sub.get("exposed_ports", []):
                port_id = f"{fqdn}:{port}"
                nodes.append({"id": port_id, "label": str(port), "type": "port", "risk": "high"})
                edges.append({"from": fqdn, "to": port_id, "label": "exposed_on"})

        # Asset/Endpoint nodes
        for asset in assets[:100]: # limit for visualization
            url = asset.get("url")
            if not url: continue
            
            parsed_host = url.split("//")[-1].split("/")[0]
            nodes.append({
                "id": url,
                "label": asset.get("path", "/"),
                "type": "endpoint", 
                "risk": "medium" if asset.get("status_code") == 200 else "low"
            })
            edges.append({"from": parsed_host, "to": url, "label": "has_endpoint"})

        return {"nodes": nodes, "edges": edges}
