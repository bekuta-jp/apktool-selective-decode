#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dex_decoder import (
    _descriptor_to_smali_path,
    _quote_smali_string,
    _unique_smali_path,
)
from androguard_disassembler import (
    _array_literal,
    _assign_branch_labels,
    _decode_mutf8_code_units,
    _debug_directives,
    _literal_comment,
    _java_decimal,
    _parameter_lines,
    _parameter_descriptors,
    _quote_char,
    _quote_string,
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
        self.assertEqual(
            "iget p0, p1, Lexample/Flow;->v0:F",
            _replace_registers(
                "iget v2, v3, Lexample/Flow;->v0:F",
                2,
            ),
        )

    def test_parameter_descriptors_include_arrays_and_wide_types(self) -> None:
        self.assertEqual(
            ["I", "[Ljava/lang/String;", "J", "D"],
            _parameter_descriptors("(I[Ljava/lang/String;JD)V"),
        )

    def test_parameter_annotations_are_rendered_without_debug_names(self) -> None:
        class Method:
            @staticmethod
            def get_descriptor() -> str:
                return "(IJLjava/lang/String;)V"

            @staticmethod
            def get_access_flags() -> int:
                return 0

        self.assertEqual(
            [
                "    .param p1    # I",
                "        .annotation build Landroidx/annotation/NonNull;",
                "        .end annotation",
                "    .end param",
                '    .param p2, "wide"    # J',
                "    .param p4    # Ljava/lang/String;",
                "        .annotation build Landroidx/annotation/Nullable;",
                "        .end annotation",
                "    .end param",
            ],
            _parameter_lines(
                Method(),
                [None, "wide"],
                [
                    [
                        "        .annotation build Landroidx/annotation/NonNull;",
                        "        .end annotation",
                    ],
                    [],
                    [
                        "        .annotation build Landroidx/annotation/Nullable;",
                        "        .end annotation",
                    ],
                ],
            ),
        )

    def test_smali_strings_escape_single_quotes_like_baksmali(self) -> None:
        expected = "\"it\\'s\""
        self.assertEqual(expected, _quote_string("it's"))
        self.assertEqual(expected, _quote_smali_string("it's"))

    def test_mutf8_decoder_preserves_surrogate_code_units(self) -> None:
        value = _decode_mutf8_code_units(bytes.fromhex("eda180edb080"))
        self.assertEqual([0xD840, 0xDC00], [ord(char) for char in value])
        self.assertEqual('"\\ud840\\udc00"', _quote_string(value))

    def test_float32_text_matches_java_style(self) -> None:
        self.assertEqual("-0.10471976", _java_decimal(-0.10471975803375244, float32=True))
        self.assertEqual("3.49066E-4", _java_decimal(0.00034906598739326, float32=True))
        self.assertEqual("9.0E-4", _java_decimal(0.0008999999845400453, float32=True))
        self.assertEqual("1.4E-45", _java_decimal(1.401298464324817e-45, float32=True))
        self.assertEqual("4.9E-324", _java_decimal(5e-324, float32=False))

    def test_char_quote_matches_baksmali(self) -> None:
        self.assertEqual("'\\\"'", _quote_char(ord('"')))

    def test_array_literals_follow_baksmali_suffix_rules(self) -> None:
        self.assertEqual("0x1", _array_literal(1, 8))
        self.assertEqual("0x100000000L", _array_literal(0x100000000, 8))

    def test_literal_comments_follow_baksmali_likelihood(self) -> None:
        self.assertEqual("2.0f", _literal_comment("const/high16", 0x40000000))
        self.assertEqual("Math.PI", _literal_comment("const-wide", 0x400921FB54442D18))
        self.assertIsNone(_literal_comment("const/high16", 0x10000))

    def test_branch_labels_are_numbered_by_kind_and_address(self) -> None:
        labels, labels_at = _assign_branch_labels(
            {"cond": {42, 10}, "goto": {42, 30}, "pswitch": {42}}
        )
        self.assertEqual(":cond_0", labels[("cond", 10)])
        self.assertEqual(":cond_1", labels[("cond", 42)])
        self.assertEqual(":goto_1", labels[("goto", 42)])
        self.assertEqual(
            [":cond_1", ":goto_1", ":pswitch_0"],
            labels_at[42],
        )

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
