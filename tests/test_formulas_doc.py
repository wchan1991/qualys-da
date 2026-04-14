#!/usr/bin/env python3
"""
Qualys DA - Formulas Doc Drift Test

Ensures every public method on AnalyticsEngine is documented in
docs/FORMULAS.md. Fails when a new metric is added to src/analytics.py
without a matching mention in the formula reference.

Run:  python -m unittest tests.test_formulas_doc -v
"""

import re
import sys
import unittest
from pathlib import Path

# Match test_qa.py's import style so src/ imports resolve when run directly.
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.analytics import AnalyticsEngine  # noqa: E402


DOC_PATH = Path(__file__).parent.parent / "docs" / "FORMULAS.md"


class FormulasDocTest(unittest.TestCase):
    def test_formulas_doc_exists(self):
        self.assertTrue(
            DOC_PATH.exists(),
            f"Expected formulas reference at {DOC_PATH}. "
            f"See tests/test_formulas_doc.py docstring for why this file must exist.",
        )

    def test_every_analytics_method_is_documented(self):
        doc = DOC_PATH.read_text(encoding="utf-8")

        missing = []
        # vars(cls) returns only attributes declared on the class itself -
        # not inherited object members like __init__ or __class__.
        for name in sorted(vars(AnalyticsEngine)):
            if name.startswith("_"):
                continue
            obj = getattr(AnalyticsEngine, name)
            if not callable(obj):
                continue
            # Require the method name as a whole word somewhere in the doc.
            # Backticks, parens, and headings all satisfy \b - we don't care
            # about the exact markup, only that the name is mentioned.
            if not re.search(rf"\b{re.escape(name)}\b", doc):
                missing.append(name)

        self.assertFalse(
            missing,
            "These AnalyticsEngine public methods are missing from "
            "docs/FORMULAS.md:\n  - " + "\n  - ".join(missing) +
            "\n\nAdd a section for each, then re-run this test.",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
