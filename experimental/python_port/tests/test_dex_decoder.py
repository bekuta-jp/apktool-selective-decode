#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dex_decoder import _descriptor_to_smali_path, _unique_smali_path
from androguard_disassembler import (
    _assign_branch_labels,
    _debug_directives,
    _parameter_descriptors,
    _replace_registers,
)


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

    def test_case_insensitive_collision_uses_baksmali_suffix(self) -> None:
        existing = {"com/example/R.smali": ""}
        self.assertEqual(
            "com/example/r.1.smali",
            _unique_smali_path("com/example/r.smali", existing),
        )

    def test_register_rewrite_does_not_change_class_path(self) -> None:
        self.assertEqual(
            "iget-object p0, p1, Landroid/support/v4/os/ResultReceiver;->mHandler:Landroid/os/Handler;",
            _replace_registers(
                "iget-object v2, v3, Landroid/support/v4/os/ResultReceiver;->mHandler Landroid/os/Handler;",
                2,
            ).replace("->mHandler Landroid", "->mHandler:Landroid"),
        )

    def test_parameter_descriptors_include_arrays_and_wide_types(self) -> None:
        self.assertEqual(
            ["I", "[Ljava/lang/String;", "J", "D"],
            _parameter_descriptors("(I[Ljava/lang/String;JD)V"),
        )

    def test_branch_labels_are_numbered_by_kind_and_address(self) -> None:
        labels, labels_at = _assign_branch_labels(
            {"cond": {42, 10}, "goto": {42, 30}}
        )
        self.assertEqual(":cond_0", labels[("cond", 10)])
        self.assertEqual(":cond_1", labels[("cond", 42)])
        self.assertEqual(":goto_1", labels[("goto", 42)])
        self.assertEqual([":cond_1", ":goto_1"], labels_at[42])

    def test_debug_local_lifecycle_uses_smali_registers(self) -> None:
        data = bytes(
            [
                0xFF,
                0x01,
                0x00,
                0x04,
                0x00,
                0x01,
                0x01,
                0x02,
                0x01,
                0x01,
                0x05,
                0x00,
                0x01,
                0x01,
                0x06,
                0x00,
                0x00,
            ]
        )
        strings = ["value", "TT;"]
        directives = _debug_directives(
            data,
            1,
            parameter_start=2,
            string_resolver=strings.__getitem__,
            type_resolver=["Ljava/lang/Object;"].__getitem__,
            initial_locals={},
        )
        self.assertEqual(
            {
                0: [
                    '.local v0, "value":Ljava/lang/Object;, "TT;"',
                ],
                2: [
                    '.end local v0    # "value":Ljava/lang/Object;, "TT;"',
                ],
                4: [
                    '.restart local v0    # "value":Ljava/lang/Object;, "TT;"',
                ],
            },
            directives,
        )


if __name__ == "__main__":
    unittest.main()
