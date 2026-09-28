from __future__ import annotations

from typing import Protocol

from phishanalyzer.models import Email, Finding


class Analyzer(Protocol):
    """A check that inspects an email and reports findings.

    Analyzers are async so that network-backed checks (threat intel, sandboxes) can run
    concurrently with the purely local ones behind the same interface.
    """

    name: str

    async def analyze(self, email: Email) -> list[Finding]: ...
