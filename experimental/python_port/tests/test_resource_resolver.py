#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from resource_resolver import resolve_framework_attribute, resolve_framework_reference


class FrameworkResourceResolverTest(unittest.TestCase):
    def test_framework_style_reference(self) -> None:
        self.assertEqual(
            "@android:style/Theme.Translucent",
            resolve_framework_reference(0x0103000F),
        )

    def test_manifest_enum(self) -> None:
        self.assertEqual(
            "landscape",
            resolve_framework_attribute(0x0101001E, 0x10, 0),
        )

    def test_manifest_flags_match_apktool_priority(self) -> None:
        self.assertEqual(
            "mcc|mnc|locale|touchscreen|keyboard|keyboardHidden|navigation|"
            "orientation|screenLayout|uiMode|screenSize|density|"
            "layoutDirection|colorMode|fontScale",
            resolve_framework_attribute(0x0101001F, 0x11, 0x400077FF),
        )

    def test_install_location_enum(self) -> None:
        self.assertEqual(
            "auto",
            resolve_framework_attribute(0x010102B7, 0x10, 0),
        )


if __name__ == "__main__":
    unittest.main()
