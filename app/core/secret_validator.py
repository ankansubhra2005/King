"""
Phase 2: Secret Validation Module.
Attempts to verify if found secrets are actually valid/live.
"""
import httpx
import asyncio
from typing import List, Dict, Any

class SecretValidator:
    def __init__(self):
        self.headers = {"User-Agent": "Mozilla/5.0"}

    async def validate_github(self, token: str) -> Dict[str, Any]:
        """Check if a Github token is valid."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get("https://api.github.com/user", headers={
                    "Authorization": f"token {token}",
                    **self.headers
                })
                if resp.status_code == 200:
                    data = resp.json()
                    return {"valid": True, "note": f"Valid Github token for user: {data.get('login')}"}
        except Exception:
            pass
        return {"valid": False}

    async def validate_aws(self, access_key: str) -> Dict[str, Any]:
        """Note: Validating AWS keys safely usually requires the AWS CLI or boto3."""
        # For now, we just flag it for manual review or use a simplistic placeholder
        return {"valid": None, "note": "AWS keys require manual verification with 'aws sts get-caller-identity'"}

    async def validate_slack(self, token: str) -> Dict[str, Any]:
        """Check if a Slack token is valid."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                data = {"token": token}
                resp = await client.post("https://slack.com/api/auth.test", data=data)
                if resp.status_code == 200:
                    res = resp.json()
                    if res.get("ok"):
                        return {"valid": True, "note": f"Valid Slack token for team: {res.get('team')}"}
        except Exception:
            pass
        return {"valid": False}

    async def validate_all(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate all findings that look like secrets."""
        tasks = []
        secret_findings = [f for f in findings if f.get("type") in ["GitHub Token", "Slack Token"]]
        
        for f in secret_findings:
            if f["type"] == "GitHub Token":
                tasks.append(self.validate_github(f["value"]))
            elif f["type"] == "Slack Token":
                tasks.append(self.validate_slack(f["value"]))
            else:
                tasks.append(asyncio.sleep(0, {"valid": None}))

        results = await asyncio.gather(*tasks)
        for f, res in zip(secret_findings, results):
            if res:
                f["validation"] = res
                if res.get("valid") is True:
                    f["confidence"] = 1.0
                    f["type"] = f"{f['type']} (VALIDATED)"
        
        return findings
