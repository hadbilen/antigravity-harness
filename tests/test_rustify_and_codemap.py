"""Hermetic seam tests for `skills/rustify/` ecosystem routing/export and `scripts/code_map.py` C/C++/Rust indexing (`ADR-0003`)."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guard import agy_hooks
from porter.analyzer import SuitabilityAnalyzer
from porter.emitters import EMITTERS
from porter.emitters.cursor import _globs_for
from porter.frontmatter import parse_frontmatter
from porter.manifest import ManifestEngine
from scripts.code_map import (
     compute_blast_radius,
    find_callers,
    profile_symbol,
)


class TestCodeMapRustAndCppSeams(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="agy_codemap_rust_cpp_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_rust_lifetimes_do_not_erase_intermediate_definitions_or_calls(self) -> None:
        """Catches single-quote regex treating Rust `'a` / `'static` lifetimes as multi-line char literals."""
        rs_file = self.root / "parser.rs"
        rs_file.write_text(
            "pub fn first_slice<'a>(input: &'a [u8]) -> &'a [u8] {\n"
            "    input\n"
            "}\n\n"
            "pub fn middle_transform(buf: &[u8]) -> usize {\n"
            "    let sliced = first_slice(buf);\n"
            "    sliced.len()\n"
            "}\n\n"
            "pub fn last_consumer<'b>(data: &'b [u8], label: &'static str) -> usize {\n"
            "    let _ = label;\n"
            "    middle_transform(data)\n"
            "}\n",
            encoding="utf-8",
        )
        prof_mid = profile_symbol("middle_transform", [self.root], base_dir=self.root)
        self.assertEqual(len(prof_mid["definitions"]), 1)
        self.assertEqual(prof_mid["definitions"][0]["line"], 5)

        first_callers = find_callers("first_slice", [self.root], base_dir=self.root)
        self.assertEqual(len(first_callers), 1)
        self.assertEqual(first_callers[0]["enclosing_scope"], "middle_transform")
        self.assertEqual(first_callers[0]["line"], 6)

        blast = compute_blast_radius("first_slice", [self.root], base_dir=self.root)
        caller_scopes = [c["caller_scope"] for c in blast["transitive_callers"]]
        self.assertIn("middle_transform", caller_scopes)
        self.assertIn("last_consumer", caller_scopes)

    def test_rust_literals_nested_comments_attributes_raw_idents_and_cargo_target_skip(self) -> None:
        """Catches Rust `b'"'`/`br#` literals, nested `/* /* */ */` comments, `#[repr(C)]` pseudo-calls, `;` prototypes, `r#` idents, turbofish calls, and Cargo `target/` pollution."""
        (self.root / "Cargo.toml").write_text('[package]\nname = "demo"\nversion = "0.1.0"\n', encoding="utf-8")
        rs_file = self.root / "lexer.rs"
        rs_file.write_text(
            "/* outer /* nested fake_call(1) */ still comment ghost_target(0); */\n"
            'extern "C" {\n'
            "    fn real_target(x: u32) -> u32;\n"
            "}\n\n"
            "#[repr(C)]\n"
            "pub struct Packet {\n"
            "    pub tag: u32,\n"
            "}\n\n"
            "pub fn generic_decode<T>(v: u32) -> u32 {\n"
            "    v\n"
            "}\n\n"
            "pub fn holder<'a>(s: &'a str) -> usize {\n"
            "    let q = '\"';\n"
            "    let byte_q = b'\"';\n"
            "    let esc = '\\'';\n"
            '    let raw = r#"unclosed " quote fn fake_def() { ghost_target(1); }"#;\n'
            '    let raw_bytes = br#"unclosed " byte quote fn ghost_two() {}"#;\n'
            '    let c_lit = c"unclosed \' cstr";\n'
            "    let r#fn = generic_decode::<Packet>(7);\n"
            "    let _ = (q, byte_q, esc, raw, raw_bytes, c_lit, r#fn);\n"
            "    unsafe { real_target(s.len() as u32) as usize }\n"
            "}\n\n"
            "pub fn r#match(v: u32) -> usize {\n"
            "    holder(\"ok\") + (v as usize)\n"
            "}\n",
            encoding="utf-8",
        )
        # Generated file inside Cargo `target/` with CACHEDIR.TAG must be skipped
        target_build = self.root / "target" / "debug" / "build" / "gen"
        target_build.mkdir(parents=True)
        (self.root / "target" / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n", encoding="utf-8")
        (target_build / "bindings.rs").write_text(
            "pub fn generated_caller() -> u32 { unsafe { real_target(99) } }\n",
            encoding="utf-8",
        )

        self.assertEqual(find_callers("ghost_target", [self.root], base_dir=self.root), [])
        self.assertEqual(find_callers("repr", [self.root], base_dir=self.root), [])
        self.assertEqual(profile_symbol("fake_def", [self.root], base_dir=self.root)["definitions"], [])
        self.assertEqual(profile_symbol("as", [self.root], base_dir=self.root)["definitions"], [])
        # `extern "C" { fn real_target(...); }` prototype must NOT register as a definition
        self.assertEqual(profile_symbol("real_target", [self.root], base_dir=self.root)["definitions"], [])

        # Raw identifier function `r#match` must be indexed
        prof_match = profile_symbol("match", [self.root], base_dir=self.root)
        self.assertEqual(len(prof_match["definitions"]), 1)

        # Turbofish `generic_decode::<Packet>(7)` must register as a call inside `holder`
        turbo_callers = find_callers("generic_decode", [self.root], base_dir=self.root)
        self.assertEqual(len(turbo_callers), 1)
        self.assertEqual(turbo_callers[0]["enclosing_scope"], "holder")

        # `real_target` must have only `holder` in `lexer.rs` (Cargo `target/` skipped)
        real_callers = find_callers("real_target", [self.root], base_dir=self.root)
        self.assertEqual(len(real_callers), 1)
        self.assertEqual(real_callers[0]["file"], "lexer.rs")
        self.assertEqual(real_callers[0]["enclosing_scope"], "holder")

    def test_c_and_cpp_definitions_headers_digit_separators_and_blast_radius(self) -> None:
        """Catches missing C/C++ file indexing, prototype/macro duplication, C++14 digit-separator erasure, or broken transitive blast radius."""
        hdr = self.root / "can_bus.h"
        hdr.write_text(
            "#ifndef CAN_BUS_H\n"
            "#define CAN_BUS_H\n"
            "#include <stdint.h>\n"
            "#define SAFE_PARSE(p, n) \\\n"
            "    do { /* multiline\n"
            "            macro comment */ can_parse_frame((p), (n)); } while (0)\n"
            "int can_parse_frame(const uint8_t *buf, uint32_t len);\n"
            "static inline uint16_t read_be16(const uint8_t *p) {\n"
            "    return (uint16_t)((p[0] << 8) | p[1]);\n"
            "}\n"
            "#endif\n",
            encoding="utf-8",
        )
        c_src = self.root / "can_bus.c"
        c_src.write_text(
            '#include "can_bus.h"\n'
            "int\n"
            "can_parse_frame(const uint8_t *buf, uint32_t len)\n"
            "{\n"
            "#ifdef TARGET_BIG_ENDIAN\n"
            "    if (len < 2) {\n"
            "#else\n"
            "    if (len < 2 || buf == 0) {\n"
            "#endif\n"
            "        return -1;\n"
            "    }\n"
            "    return (int)read_be16(buf);\n"
            "}\n\n"
            "void log_frame(const char *fmt, ...) __attribute__((format(printf, 1, 2))) {\n"
            "    (void)fmt;\n"
            "}\n",
            encoding="utf-8",
        )
        cpp_src = self.root / "ecu_controller.cpp"
        cpp_src.write_text(
            '#include "can_bus.h"\n'
            "static uint32_t clamp_timeout(uint32_t v) { return v; }\n"
            "static void init_hw(void) {}\n"
            "static void close_bus(void) {}\n"
            "static int g_boot = can_parse_frame(0, 0);\n\n"
            "struct __attribute__((packed)) FrameHeader { uint8_t id; };\n\n"
            "class EcuController {\n"
            "public:\n"
            "    EcuController(uint32_t timeout_us) : timeout_{clamp_timeout(timeout_us)} { init_hw(); }\n"
            "    ~EcuController();\n"
            "    int dispatch(const uint8_t *raw, uint32_t len = 0) const noexcept;\n"
            "    EcuController& operator=(const EcuController& rhs) { copy_state(); return *this; }\n"
            "private:\n"
            "    void copy_state() {}\n"
            "    uint32_t timeout_;\n"
            "};\n\n"
            "EcuController::~EcuController() {\n"
            "    close_bus();\n"
            "}\n\n"
            "int EcuController::dispatch(const uint8_t *raw, uint32_t len) const noexcept {\n"
            "    constexpr uint32_t kMaxWait = 100'000;\n"
            '    const char *raw_tag = R"---(unclosed " fn ghost_cpp() {})---";\n'
            '    const char *cat = "%" "d ";\n'
            "    char quote_ch = '\"';\n"
            "    switch (quote_ch) { case'\"': log_frame(cat); break; default: break; }\n"
            "    (void)raw_tag;\n"
            "    if (len == 0 || kMaxWait == 0) {\n"
            "        return -1;\n"
            "    }\n"
            "    return can_parse_frame(raw, len);\n"
            "}\n\n"
            "template <typename T = int>\n"
            "auto decode_pair(const uint8_t *p, uint32_t n) -> T {\n"
            "    return static_cast<T>(can_parse_frame(p, n));\n"
            "}\n",
            encoding="utf-8",
        )
        # Prototype & SAFE_PARSE macro in can_bus.h must NOT duplicate definition in can_bus.c
        prof_parse = profile_symbol("can_parse_frame", [self.root], base_dir=self.root)
        self.assertEqual(len(prof_parse["definitions"]), 1)
        self.assertEqual(prof_parse["definitions"][0]["file"], "can_bus.c")

        # `#ifdef / #else` dual-`{` inside `can_parse_frame` must NOT swallow `log_frame` below it
        prof_log = profile_symbol("log_frame", [self.root], base_dir=self.root)
        self.assertEqual(len(prof_log["definitions"]), 1)
        log_callers = find_callers("log_frame", [self.root], base_dir=self.root)
        self.assertEqual(len(log_callers), 1)
        self.assertEqual(log_callers[0]["enclosing_scope"], "EcuController.dispatch")

        # C++ `::` query normalization (`EcuController::dispatch`)
        prof_dispatch = profile_symbol("EcuController::dispatch", [self.root], base_dir=self.root)
        self.assertEqual(len(prof_dispatch["definitions"]), 1)

        # C++11 brace member-initializer `: timeout_{clamp_timeout(timeout_us)} { init_hw(); }`
        hw_callers = find_callers("init_hw", [self.root], base_dir=self.root)
        self.assertEqual(len(hw_callers), 1)
        self.assertEqual(hw_callers[0]["enclosing_scope"], "EcuController.EcuController")
        clamp_callers = find_callers("clamp_timeout", [self.root], base_dir=self.root)
        self.assertEqual(len(clamp_callers), 1)
        self.assertEqual(clamp_callers[0]["enclosing_scope"], "EcuController.EcuController")

        # Out-of-line destructor `EcuController::~EcuController` and `operator=`
        dtor_prof = profile_symbol("EcuController::~EcuController", [self.root], base_dir=self.root)
        self.assertEqual(len(dtor_prof["definitions"]), 1)
        self.assertEqual(dtor_prof["definitions"][0]["kind"], "method")
        close_callers = find_callers("close_bus", [self.root], base_dir=self.root)
        self.assertEqual(close_callers[0]["enclosing_scope"], "EcuController.~EcuController")
        copy_callers = find_callers("copy_state", [self.root], base_dir=self.root)
        self.assertEqual(len(copy_callers), 1)

        # Module-scope initializer `g_boot`, `dispatch`, and defaulted template `decode_pair` callers (zero macro caller from can_bus.h)
        parse_callers = find_callers("can_parse_frame", [self.root], base_dir=self.root)
        caller_scopes = {c["enclosing_scope"] for c in parse_callers}
        self.assertEqual(caller_scopes, {"<module>", "EcuController.dispatch", "decode_pair"})
        self.assertTrue(all(c["file"] == "ecu_controller.cpp" for c in parse_callers))

        # Transitive blast radius from inline header helper `read_be16` -> `can_parse_frame` -> `EcuController.dispatch` & `decode_pair`
        blast = compute_blast_radius("read_be16", [self.root], base_dir=self.root)
        self.assertEqual(
            blast["affected_files"],
            ["can_bus.c", "can_bus.h", "ecu_controller.cpp"],
        )
        self.assertEqual(blast["tier_recommendation"], "Tier 2")

    def test_cpp_trailing_qualifier_stripper_is_linear_time_no_redos(self) -> None:
        """Catches exponential `O(2^N)` backtracking on whitespace/comment-padded C/C++ declarations."""
        padded_c = self.root / "padded.cpp"
        padded_c.write_text(
            "int /* " + ("x" * 64) + " */ fast_fn(int v) { return v; }\n"
            + "auto " + (" " * 64) + "trailing_fn(int v) -> const int { return fast_fn(v); }\n",
            encoding="utf-8",
        )
        t0 = time.monotonic()
        prof = profile_symbol("fast_fn", [self.root], base_dir=self.root)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 0.5, f"C++ declaration indexing took {elapsed:.3f}s (potential ReDoS)")
        self.assertEqual(len(prof["definitions"]), 1)
        self.assertEqual(len(prof["callers"]), 1)
        self.assertEqual(prof["callers"][0]["enclosing_scope"], "trailing_fn")


class TestRustifySkillAndRoutingSeams(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="agy_rustify_route_"))
        self.cfg_dir = self.tmp / "gemini_config"
        self.state_dir = self.tmp / "state"
        self.cfg_dir.mkdir(parents=True)
        self.state_dir.mkdir(parents=True)
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "ANTIGRAVITY_CONFIG_DIR": str(self.cfg_dir),
                "AGY_GUARD_STATE_DIR": str(self.state_dir),
            },
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_rustify_positive_bilingual_and_ffi_triggers(self) -> None:
        """Catches missing single-branch bilingual Cross-Language -> Rust, comma-qualified, FFI, or priority routing in SKILL_HINTS."""
        positive_prompts = [
            "/rustify src/codec.c",
            "Incrementally rustify legacy_codec.cpp.",
            "Port this C++ packet parser into idiomatic, memory-safe Rust.",
            "Migrate C, C++, or Python modules into Rust.",
            "Bu C/C++ sürücüsünü Rust'a çevir ve dilimlerle arındır.",
            "C/C++'dan Rust'a geçiş mimarisi çıkar.",
            "Expose `#[cxx::bridge]` and cbindgen headers for the host.",
            "Wrap this hot loop with PyO3 and maturin.",
            "Use rustify to fix this segfault and add boundary-value tests.",
        ]
        for idx, prompt in enumerate(positive_prompts):
            with self.subTest(idx=idx, prompt=prompt):
                res = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-rustify-pos-{idx}", "prompt": prompt}
                )
                self.assertIn("injectSteps", res, f"Expected PreInvocation hint for: {prompt}")
                msg = res["injectSteps"][0]["ephemeralMessage"]
                self.assertIn("`rustify`", msg)
                self.assertIn("skills/rustify/SKILL.md", msg)

    def test_rustify_rejects_intra_rust_refactor_cargo_bump_and_filepath_false_positives(self) -> None:
        """Catches false-positive `rustify` routing on intra-Rust refactoring, Cargo bumps, edition bumps, or `rustify.rs` paths."""
        negative_prompts = [
            "Refactor this Rust struct in src/rustify/parser.rs to extract a helper function.",
            "Edit rustify.rs and rustify.py to fix formatting.",
            "Bump tokio from 1.38.0 to 1.40.0 in Cargo.toml.",
            "Bump pyo3 from 0.21 to 0.22 in Cargo.toml.",
            "Migrate this crate to Rust 2024.",
            "Migrate this workspace to Rust edition 2024.",
            "Rewrite this unsafe helper into safe Rust.",
            "Fix the borrow checker lifetime error in crates/engine/src/lib.rs.",
            "Bu Rust servisinin bellek kullanımını düşür ve kare hızını artır.",
            "Modernize this old VB6 desktop application to a modern cross-platform web stack.",
        ]
        for idx, prompt in enumerate(negative_prompts):
            with self.subTest(idx=idx, prompt=prompt):
                res = agy_hooks.handle_pre_invocation(
                    {"conversationId": f"conv-rustify-neg-{idx}", "prompt": prompt}
                )
                msg = res.get("injectSteps", [{}])[0].get("ephemeralMessage", "")
                self.assertNotIn("`rustify`", msg, f"False positive `rustify` hint injected for: {prompt}")

    def test_rustify_porter_inspection_and_cursor_export_globs_and_reference_links(self) -> None:
        """Catches missing subfiles in manifest, constitutional hygiene violations, `zero-trust` glob collisions, or missing Cursor globs/links."""
        skill_path = REPO_ROOT / "skills" / "rustify" / "SKILL.md"
        self.assertTrue(skill_path.is_file(), "skills/rustify/SKILL.md must exist")

        report = SuitabilityAnalyzer(REPO_ROOT).analyze(
            skill_path.read_text(encoding="utf-8"),
            source_identifier=str(skill_path),
        )
        self.assertEqual(report.constitutional_score, 100)
        self.assertEqual(report.issues, [])

        self.assertEqual(_globs_for("zero-trust"), "")
        self.assertEqual(_globs_for("trust-boundary"), "")

        manifest = ManifestEngine(REPO_ROOT).build_manifest(deterministic=True)
        rustify_entries = [s for s in manifest.skills if s.get("name") == "rustify"]
        self.assertEqual(len(rustify_entries), 1)
        subfiles = rustify_entries[0].get("subfiles") or {}
        self.assertIn("references/c-cpp-abi-and-embedded.md", subfiles)
        self.assertIn("references/managed-go-python.md", subfiles)

        out_dir = self.tmp / "cursor_export"
        plan, _ = EMITTERS["cursor"].plan(manifest, out_dir)
        mdc_path = out_dir / ".cursor" / "rules" / "skill-rustify.mdc"
        self.assertIn(mdc_path, plan)
        meta, body = parse_frontmatter(plan[mdc_path])
        glob_list = [g.strip() for g in str(meta.get("globs", "")).split(",") if g.strip()]
        self.assertEqual(
            glob_list,
            [
                "**/*.rs",
                "**/Cargo.toml",
                "**/*.c",
                "**/*.h",
                "**/*.cpp",
                "**/*.cc",
                "**/*.cxx",
                "**/*.hpp",
                "**/*.hh",
                "**/*.hxx",
            ],
        )
        self.assertIn(".cursor/skills/rustify/references/c-cpp-abi-and-embedded.md", body)
        self.assertIn(".cursor/skills/rustify/references/managed-go-python.md", body)


if __name__ == "__main__":
    unittest.main()
