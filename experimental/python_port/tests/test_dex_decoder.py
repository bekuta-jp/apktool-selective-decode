#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dex_decoder import _descriptor_to_smali_path, _unique_smali_path


class SmaliPathTest(unittest.TestCase):
    def test_descriptor_path(self) -> None:
        self.assertEqual(
            "com/example/App.smali",
            _descriptor_to_smali_path("Lcom/example/App;"),
        )

    def test_duplicate_descriptor_uses_baksmali_suffix(self) -> None:
        existing = {
            "com/example/App.smali": "",
            "com/example/App.1.smali": "",
        }
        self.assertEqual(
            "com/example/App.2.smali",
            _unique_smali_path("com/example/App.smali", existing),
        )


if __name__ == "__main__":
    unittest.main()
