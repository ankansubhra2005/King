"""
Phase 2 - Module 8c: SQL Injection (SQLi) Detection Engine
Detects Error-based, Time-based, and Boolean-based SQL Injection.
"""
import asyncio
import httpx
import time
from typing import List, Dict, Optional
from urllib.parse import urlencode, urlparse, parse_qs
from app.core.payload_manager import load_payloads
from app.core.verbose import v_info, v_finding

# Load SQLi payloads
_SQLI_PAYLOADS = load_payloads("sqli")

# SQL Error patterns for different databases
SQL_ERRORS = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql",
        "check the manual that corresponds to your mysql server version",
        "unclosed quotation mark after the character string",
    ],
    "PostgreSQL": [
        "postgresql query failed",
        "warning: pg_",
        "invalid input syntax for",
        "severity: error",
    ],
    "Microsoft SQL Server": [
        "driver] [microsoft] [sql server",
        "sqlserver error",
        "dbo.",
        "invalid column name",
    ],
    "Oracle": [
        "ora-00933",
        "oracle error",
        "oracle parameter",
    ],
    "SQLite": [
        "sqlite3_prepare",
        "sqlite_error",
    ]
}

class SQLIEngine:
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.payloads = _SQLI_PAYLOADS if _SQLI_PAYLOADS else ["'", "''", "\"", "1' OR '1'='1", "1' AND 1=1"]

    async def test_error_based(self, url: str, param: str) -> List[Dict]:
        """Inject single/double quotes to see if the server returns database errors."""
        findings = []
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)
        
        # Simple test characters for error triggering
        test_chars = ["'", "\"", "\\", "')"]
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            for char in test_chars:
                test_params = {k: v[0] for k, v in base_params.items()}
                test_params[param] = test_params[param] + char if param in test_params else char
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                
                try:
                    resp = await client.get(test_url, headers={"User-Agent": "Mozilla/5.0"})
                    body = resp.text.lower()
                    
                    for db, errors in SQL_ERRORS.items():
                        for err in errors:
                            if err in body:
                                finding = {
                                    "type": f"SQL Injection (Error-based: {db})",
                                    "url": test_url,
                                    "parameter": param,
                                    "payload": char,
                                    "severity": "critical",
                                    "confidence": 0.90,
                                    "evidence": f"Found {db} error: {err}",
                                    "owasp_category": "A03:2021-Injection",
                                    "suggested_next_step": "Try UNION select or boolean-based discovery",
                                    "source": "king-internal",
                                }
                                v_finding(f"SQLi ({db})", "critical", test_url, f"param={param}")
                                findings.append(finding)
                                return findings # Stop once we confirmed it's vulnerable
                except Exception:
                    pass
        return findings

    async def test_time_based(self, url: str, param: str) -> List[Dict]:
        """Inject SLEEP() / WAITFOR DELAY and check if response is delayed."""
        findings = []
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)
        
        # Payloads that trigger ~5s delay
        time_payloads = [
            ("1' AND SLEEP(5)--", 5),
            ("1 AND SLEEP(5)", 5),
            ("'; WAITFOR DELAY '0:0:5'--", 5),
            ("' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", 5),
        ]
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout + 10) as client:
            for payload, delay_target in time_payloads:
                test_params = {k: v[0] for k, v in base_params.items()}
                test_params[param] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                
                start_time = time.time()
                try:
                    await client.get(test_url, headers={"User-Agent": "Mozilla/5.0"})
                    elapsed = time.time() - start_time
                    
                    if elapsed >= delay_target:
                        # Double check to avoid false positives (maybe server is just slow)
                        # Hit original URL again to see baseline
                        start_baseline = time.time()
                        await client.get(url)
                        baseline = time.time() - start_baseline
                        
                        if elapsed > (baseline + delay_target - 1):
                            finding = {
                                "type": "SQL Injection (Time-based)",
                                "url": test_url,
                                "parameter": param,
                                "payload": payload,
                                "severity": "critical",
                                "confidence": 0.85,
                                "evidence": f"Response delayed by {elapsed:.2f}s (baseline: {baseline:.2f}s)",
                                "owasp_category": "A03:2021-Injection",
                                "suggested_next_step": "Confirm with conditional delays (e.g., if(1=1,sleep(5),0))",
                                "source": "king-internal",
                            }
                            v_finding("SQLi (Time-based)", "critical", test_url, f"param={param}")
                            findings.append(finding)
                            return findings
                except Exception:
                    pass
        return findings

    async def test_boolean_based(self, url: str, param: str) -> List[Dict]:
        """Compare results of TRUE vs FALSE injections."""
        findings = []
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)
        
        # Boolean pairs
        pairs = [
            ("' AND 1=1--", "' AND 1=2--"),
            ("' OR 1=1--", "' OR 1=2--"),
        ]
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            for true_pay, false_pay in pairs:
                # 1. Get Baseline
                try:
                    resp_base = await client.get(url)
                    base_len = len(resp_base.text)
                    
                    # 2. Get True result
                    t_params = {k: v[0] for k, v in base_params.items()}
                    t_params[param] = f"{t_params.get(param, '')}{true_pay}"
                    t_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(t_params)}"
                    resp_true = await client.get(t_url)
                    true_len = len(resp_true.text)
                    
                    # 3. Get False result
                    f_params = {k: v[0] for k, v in base_params.items()}
                    f_params[param] = f"{f_params.get(param, '')}{false_pay}"
                    f_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(f_params)}"
                    resp_false = await client.get(f_url)
                    false_len = len(resp_false.text)
                    
                    # Heuristic: True result is like baseline, False result is significantly different
                    # Or True result is different from False result
                    if abs(true_len - false_len) > 100: # Simple threshold
                         # Confirm True is close to baseline if possible
                         if abs(true_len - base_len) < 50:
                            finding = {
                                "type": "SQL Injection (Boolean-based)",
                                "url": t_url,
                                "parameter": param,
                                "payload": true_pay,
                                "severity": "high",
                                "confidence": 0.70,
                                "evidence": f"Response size difference: TRUE({true_len}) vs FALSE({false_len})",
                                "owasp_category": "A03:2021-Injection",
                                "suggested_next_step": "Use sqlmap for full data exfiltration",
                                "source": "king-internal",
                            }
                            v_finding("SQLi (Boolean)", "high", t_url, f"param={param}")
                            findings.append(finding)
                            return findings
                except Exception:
                    pass
        return findings

    async def scan(self, assets: List[Dict]) -> List[Dict]:
        """Scan assets for SQL Injection — STRICTLY SEQUENTIAL."""
        all_findings = []
        
        # Only test URLs with parameters
        for asset in assets:
            url = asset.get("url", "")
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            
            if params:
                for param in params:
                    # Sequential test for each parameter
                    eb = await self.test_error_based(url, param)
                    all_findings.extend(eb)
                    
                    tb = await self.test_time_based(url, param)
                    all_findings.extend(tb)
                    
                    bb = await self.test_boolean_based(url, param)
                    all_findings.extend(bb)
            
        return all_findings
