"""
Phase 3 - MCP (Model Context Protocol) Security Engine
Identifies and probes Model Context Protocol server endpoints for:
- Unauthenticated tool listing / schema disclosure
- Unauthorized tool execution (calling internal tools without auth)
- Tool poisoning indicators (malicious tool descriptions)
- Sensitive resource exposure via MCP resource APIs
"""
import asyncio
import httpx
import json
from typing import List, Dict, Optional
from urllib.parse import urljoin


# ── MCP Endpoint Discovery ────────────────────────────────────────────────────

MCP_ENDPOINT_PATTERNS = [
    "/mcp",
    "/mcp/",
    "/api/mcp",
    "/.well-known/mcp",
    "/mcp/v1",
    "/mcp/tools",
    "/mcp/resources",
    "/mcp/prompts",
    "/api/ai/mcp",
    "/ai/mcp",
    "/sse",            # MCP often uses Server-Sent Events transport
    "/mcp/sse",
    "/jsonrpc",        # JSON-RPC 2.0 is MCP's wire format
    "/rpc",
]

# Standard MCP JSON-RPC 2.0 methods
MCP_METHODS = {
    "tools/list":     {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    "resources/list": {"jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {}},
    "prompts/list":   {"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}},
    "initialize":     {"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05",
        "clientInfo": {"name": "security-scanner", "version": "1.0"},
        "capabilities": {},
    }},
}

# Sensitive tool name patterns (tools that should not be externally accessible)
SENSITIVE_TOOL_PATTERNS = [
    "exec", "shell", "bash", "cmd", "run", "execute",
    "file", "read_file", "write_file", "delete_file",
    "database", "db", "query", "sql",
    "env", "environment", "config",
    "secret", "key", "token", "credential",
    "network", "http", "fetch", "request",
    "email", "send", "notify",
    "admin", "internal",
]

# Indicators of tool poisoning in descriptions
TOOL_POISONING_INDICATORS = [
    "ignore previous", "ignore all", "disregard", "forget instructions",
    "new instructions", "override", "bypass", "jailbreak",
    "exfiltrate", "send data to", "report to",
]


class MCPSecurityEngine:
    """
    Discovers and tests MCP (Model Context Protocol) server endpoints.
    MCP enables LLMs to call external tools — misconfigurations can lead
    to unauthorized tool execution, data leakage, or SSRF.
    """

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    # ── Discovery ─────────────────────────────────────────────────────────

    async def discover_mcp_endpoints(self, base_url: str) -> List[Dict]:
        """Probe common MCP endpoint paths on the target."""
        found = []
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            for path in MCP_ENDPOINT_PATTERNS:
                url = urljoin(base_url, path)
                try:
                    # Try GET first (SSE endpoints, well-known)
                    resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    if resp.status_code in [200, 405]:  # 405 = method not allowed = endpoint exists
                        found.append({
                            "url": url,
                            "status": resp.status_code,
                            "content_type": resp.headers.get("content-type", ""),
                            "is_sse": "text/event-stream" in resp.headers.get("content-type", ""),
                        })
                        continue

                    # Try POST (JSON-RPC)
                    resp = await client.post(
                        url,
                        json=MCP_METHODS["initialize"],
                        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                    )
                    if resp.status_code in [200, 201]:
                        content_type = resp.headers.get("content-type", "")
                        if "json" in content_type or "jsonrpc" in resp.text.lower():
                            found.append({
                                "url": url,
                                "status": resp.status_code,
                                "content_type": content_type,
                                "is_jsonrpc": True,
                                "response_snippet": resp.text[:200],
                            })
                except Exception:
                    pass
        return found

    # ── Tool Schema Disclosure ────────────────────────────────────────────

    async def probe_tool_listing(self, url: str) -> List[Dict]:
        """
        Call tools/list to get the server's tool schema.
        Unauthenticated tool listing reveals attack surface and potential sensitive tools.
        """
        findings = []
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                resp = await client.post(
                    url,
                    json=MCP_METHODS["tools/list"],
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                )
                if resp.status_code not in [200, 201]:
                    return []

                try:
                    data = resp.json()
                except Exception:
                    return []

                tools = data.get("result", {}).get("tools", [])
                if not tools:
                    return []

                # Found the tool list — flag as info
                findings.append({
                    "type": "MCP Security — Unauthenticated Tool Schema Disclosure",
                    "url": url,
                    "tool_count": len(tools),
                    "tool_names": [t.get("name") for t in tools],
                    "severity": "medium",
                    "confidence": 0.90,
                    "evidence": f"MCP server returned {len(tools)} tools without authentication",
                    "suggested_next_step": "Enumerate all tools, check for sensitive ones, attempt unauthorized execution",
                })

                # Check each tool for sensitive names
                for tool in tools:
                    name = tool.get("name", "").lower()
                    description = tool.get("description", "").lower()

                    # High-risk tool names
                    if any(pat in name for pat in SENSITIVE_TOOL_PATTERNS):
                        findings.append({
                            "type": "MCP Security — Sensitive Tool Exposed",
                            "url": url,
                            "tool_name": tool.get("name"),
                            "tool_description": tool.get("description", "")[:300],
                            "tool_schema": tool.get("inputSchema", {}),
                            "severity": "high",
                            "confidence": 0.85,
                            "evidence": f"Tool '{tool.get('name')}' matches sensitive pattern",
                            "suggested_next_step": f"Attempt to call tool '{tool.get('name')}' via tools/call — may achieve RCE, SSRF, or data access",
                        })

                    # Tool poisoning in description
                    if any(ind in description for ind in TOOL_POISONING_INDICATORS):
                        findings.append({
                            "type": "MCP Security — Tool Poisoning Indicator",
                            "url": url,
                            "tool_name": tool.get("name"),
                            "suspicious_description": tool.get("description", "")[:300],
                            "severity": "critical",
                            "confidence": 0.75,
                            "evidence": "Tool description contains prompt injection / poisoning language",
                            "suggested_next_step": "Investigate tool origin — may indicate supply chain attack or malicious plugin",
                        })

        except Exception:
            pass
        return findings

    # ── Unauthorized Tool Execution ───────────────────────────────────────

    async def test_unauthorized_tool_call(self, url: str, tool_name: str, args: dict = None) -> Optional[Dict]:
        """
        Attempt to call a tool without authentication.
        If successful, this is a critical unauthenticated tool execution vulnerability.
        """
        payload = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args or {},
            },
        }
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                resp = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                )
                if resp.status_code in [200, 201]:
                    try:
                        data = resp.json()
                    except Exception:
                        return None
                    # If we get a result (not an auth error), execution succeeded
                    if "result" in data and "error" not in data:
                        return {
                            "type": "MCP Security — Unauthorized Tool Execution",
                            "url": url,
                            "tool_name": tool_name,
                            "arguments_sent": args,
                            "response": str(data.get("result", ""))[:500],
                            "severity": "critical",
                            "confidence": 0.90,
                            "evidence": "Tool executed without authentication, result received",
                            "suggested_next_step": "Escalate to RCE/data exfiltration depending on tool capability",
                        }
        except Exception:
            pass
        return None

    # ── Resource Disclosure ───────────────────────────────────────────────

    async def probe_resource_listing(self, url: str) -> List[Dict]:
        """Call resources/list to check for exposed MCP resources."""
        findings = []
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                resp = await client.post(
                    url,
                    json=MCP_METHODS["resources/list"],
                    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
                )
                if resp.status_code in [200, 201]:
                    try:
                        data = resp.json()
                    except Exception:
                        return []
                    resources = data.get("result", {}).get("resources", [])
                    if resources:
                        findings.append({
                            "type": "MCP Security — Resource Schema Disclosure",
                            "url": url,
                            "resource_count": len(resources),
                            "resources": [r.get("uri", r.get("name", "")) for r in resources[:10]],
                            "severity": "medium",
                            "confidence": 0.85,
                            "evidence": f"{len(resources)} MCP resources accessible without auth",
                            "suggested_next_step": "Read each resource URI via resources/read to check for sensitive data",
                        })
        except Exception:
            pass
        return findings

    # ── Main Scanner ──────────────────────────────────────────────────────

    async def scan(self, base_url: str, assets: List[Dict] = None) -> List[Dict]:
        """
        Full MCP security scan:
        1. Discover MCP endpoints
        2. Probe tool/resource listings without auth
        3. Attempt unauthorized tool execution on sensitive tools
        """
        all_findings = []

        endpoints = await self.discover_mcp_endpoints(base_url)
        if not endpoints:
            return []

        for ep in endpoints:
            url = ep["url"]

            # Tool and resource schema
            tool_findings = await self.probe_tool_listing(url)
            resource_findings = await self.probe_resource_listing(url)
            all_findings.extend(tool_findings)
            all_findings.extend(resource_findings)

            # Attempt to call sensitive tools without auth
            for finding in tool_findings:
                if finding.get("type") == "MCP Security — Sensitive Tool Exposed":
                    tool_name = finding.get("tool_name")
                    result = await self.test_unauthorized_tool_call(url, tool_name, {})
                    if result:
                        all_findings.append(result)

        return all_findings
