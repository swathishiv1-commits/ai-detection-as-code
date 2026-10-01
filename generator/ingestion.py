"""
generator/ingestion.py

Pulls CTI / threat report text from a paste, local file, or URL, and cleans it
into plain text suitable for prompting an LLM.

Deliberately conservative: we just need clean prose for the model to reason
over, not a perfect article extraction.
"""

from __future__ import annotations

import re
from pathlib import Path

import requests
from bs4 import BeautifulSoup

MAX_CHARS = 12_000  # keep prompt size sane; truncate long reports


def clean_text(raw: str) -> str:
    """Collapse whitespace and strip obvious boilerplate noise."""
    text = re.sub(r"\s+", " ", raw).strip()
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS] + " ...[truncated]"
    return text


def from_paste(text: str) -> str:
    return clean_text(text)


def from_file(path: str) -> str:
    content = Path(path).read_text(encoding="utf-8", errors="ignore")
    return clean_text(content)


def from_url(url: str, timeout: int = 15) -> str:
    """
    Fetch a page and strip it down to readable text. This is a best-effort
    extractor (drops nav/script/style) -- good enough for blog-style CTI
    write-ups, not a substitute for a real readability library on messy sites.
    """
    resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    for tag in soup(["script", "style", "nav", "header", "footer", "form"]):
        tag.decompose()

    text = soup.get_text(separator=" ")
    return clean_text(text)


def ingest(*, text: str | None = None, file: str | None = None, url: str | None = None) -> str:
    """Single entrypoint: exactly one of text/file/url should be provided."""
    provided = [v for v in (text, file, url) if v]
    if len(provided) != 1:
        raise ValueError("Provide exactly one of: text, file, url")

    if text:
        return from_paste(text)
    if file:
        return from_file(file)
    return from_url(url)  # type: ignore[arg-type]
