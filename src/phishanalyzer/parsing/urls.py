"""Extract URLs from plain-text and HTML bodies."""

from __future__ import annotations

import re
import warnings

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

from phishanalyzer.models import Url

# Ported from the hackathon version: http(s)/ftp URLs and bare www. links.
_URL_RE = re.compile(r"((?:https?|ftp)://[^\s/$.?#].[^\s<>\"'\]\[]*|www\.[^\s<>\"'\]\[]+)", re.I)
_TRAILING = ".,;:!?)]}>'\""


def _clean(url: str) -> str:
    # Strip sentence punctuation that the regex swallowed, e.g. "(see https://x.com/a)."
    while url and url[-1] in _TRAILING:
        url = url[:-1]
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


def _is_web_url(url: str) -> bool:
    return url.lower().startswith(("http://", "https://", "ftp://", "www."))


def urls_from_text(text: str) -> list[Url]:
    return [Url(url=_clean(m), source="text") for m in _URL_RE.findall(text or "")]


def _soup(html: str) -> BeautifulSoup:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", MarkupResemblesLocatorWarning)
        soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["style", "script", "head"]):
        tag.decompose()
    return soup


def html_to_text(html: str) -> str:
    """Visible text of an HTML body, whitespace-normalised per line."""
    if not html:
        return ""
    text = _soup(html).get_text("\n")
    return "\n".join(line for raw in text.splitlines() if (line := " ".join(raw.split())))


def urls_from_html(html: str) -> list[Url]:
    if not html:
        return []
    soup = _soup(html)
    found: list[Url] = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if _is_web_url(href):
            text = " ".join(a.get_text(" ", strip=True).split()) or None
            found.append(Url(url=_clean(href), display_text=text, source="html"))
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        found.append(Url(url=_clean(action) if action else "", source="form"))
    # URLs written out as text (not wrapped in <a>) are still clickable in many clients.
    found.extend(urls_from_text(soup.get_text(" ")))
    return found


def extract_urls(text: str, html: str) -> list[Url]:
    """All URLs in the email, de-duplicated; the richest occurrence of each URL wins.

    HTML links come first so the entry that carries anchor text is kept.
    """
    seen: dict[str, Url] = {}
    for url in [*urls_from_html(html), *urls_from_text(text)]:
        key = url.url if url.source != "form" else f"form:{url.url}"
        if key not in seen:
            seen[key] = url
    return list(seen.values())
