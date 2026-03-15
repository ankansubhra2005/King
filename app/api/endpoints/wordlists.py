"""
API Endpoint: Custom Wordlist & Payload Management
Users can upload wordlist/payload files via the REST API.
"""
from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from fastapi.responses import JSONResponse
from typing import Optional
import os
from pathlib import Path
from app.core.payload_manager import (
    list_available, install_custom, load_wordlist, CUSTOM_DIR
)

router = APIRouter()

ALLOWED_EXTENSIONS = {".txt", ".list"}
MAX_FILE_SIZE_MB = 10


@router.get("/", summary="List all available wordlists and payloads")
async def list_wordlists(category: Optional[str] = Query(None, description="Filter by category")):
    """
    Returns all built-in and custom wordlists with entry counts.

    Categories: subdomains, directories, xss, ssrf, lfi, sqli, extensions, headers
    """
    return list_available(category)


@router.post("/{category}", summary="Upload a custom wordlist or payload file")
async def upload_wordlist(
    category: str,
    file: UploadFile = File(..., description="Text file with one entry per line"),
):
    """
    Upload a custom wordlist/payload file for a given category.

    Supported categories: subdomains, directories, xss, ssrf, lfi, sqli, extensions, headers

    The file will be merged with built-in defaults automatically on next scan.
    Comments (lines starting with #) and blank lines are ignored.
    """
    valid_categories = ["subdomains", "directories", "xss", "ssrf", "lfi", "sqli", "extensions", "headers"]
    if category not in valid_categories:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid category '{category}'. Valid: {valid_categories}"
        )

    # Validate extension
    suffix = Path(file.filename or "file.txt").suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Only .txt and .list files are allowed.")

    # Read content
    content = await file.read()
    if len(content) > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File exceeds {MAX_FILE_SIZE_MB}MB limit.")

    # Save to custom dir
    CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
    dest = CUSTOM_DIR / f"{category}_custom_{file.filename}"
    dest.write_bytes(content)

    # Count valid entries
    lines = [l.strip() for l in content.decode("utf-8", errors="ignore").splitlines()
             if l.strip() and not l.startswith("#")]

    return {
        "status": "uploaded",
        "category": category,
        "filename": file.filename,
        "saved_as": str(dest),
        "valid_entries": len(lines),
        "message": f"✅ {len(lines)} entries loaded into '{category}' category. Will be used in all future scans.",
    }


@router.delete("/{category}/{filename}", summary="Remove a custom wordlist file")
async def delete_wordlist(category: str, filename: str):
    """Delete a previously uploaded custom wordlist."""
    target = CUSTOM_DIR / filename
    if not target.exists() or category not in filename:
        raise HTTPException(status_code=404, detail="File not found.")
    target.unlink()
    return {"status": "deleted", "filename": filename}


@router.get("/{category}/preview", summary="Preview merged wordlist for a category")
async def preview_wordlist(
    category: str,
    limit: int = Query(50, description="Max entries to return")
):
    """Preview the merged (built-in + custom) wordlist for a category."""
    entries = load_wordlist(category)
    return {
        "category": category,
        "total_entries": len(entries),
        "preview": entries[:limit],
    }
