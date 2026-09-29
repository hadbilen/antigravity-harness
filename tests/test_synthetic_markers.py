"""
tests/test_synthetic_markers.py — Tests for scripts/check_synthetic_markers.py
Part of Antigravity Harness (https://github.com/hadbilen/antigravity-harness)
Standard library only; no network.
"""

from __future__ import annotations

import hermetic  # noqa: F401  (isolates HOME/state before anything else is imported)

import dataclasses
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import check_synthetic_markers as csm

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_synthetic_markers.py"

CAFE = (
    "Nestled in the heart of the city, our café stands as a testament to the town's rich cultural\n"
    "heritage — it's not just a coffee shop, it's a gathering place. Additionally, the menu boasts a\n"
    "diverse array of pastries, showcasing our commitment to quality. While specific details about\n"
    "opening hours are not widely documented, it's important to note that hours may vary.\n"
)

TURKISH = (
    "Bu uygulama sadece bir araç değil, aynı zamanda bir yaşam tarzıdır. İstanbul'un kalbinde yer alan "
    "ofisimiz, geniş bir yelpazede hizmet sunuyor ve sektörde kritik bir rol oynamaktadır. Kahve bir içecek "
    "değil, bir deneyimdir.\n"
    "\n"
    "Festival her yıl binlerce kişiyi ağırlıyor, kentin kültürel mirasının önemini vurgulayarak. Şehir, zengin "
    "bir kültürel mozaiğe ev sahipliği yapmaktadır. Unutmamak gerekir ki kusursuz bir deneyim için planlama "
    "şarttır.\n"
    "\n"
    "Sonuç olarak, bu bölge ziyaretçilerine çok şey sunuyor. Umarım bu yardımcı olur.\n"
)

TURKISH_CLEAN = (
    "Ofisimiz Kadıköy'de, iskeleye beş dakika uzaklıkta. Her sabah on iki çeşit poğaça pişiriyoruz. "
    "Hava soğuk değil, sıcak. Çalışma saatleri mevsime göre değişiyor, bu yüzden gelmeden önce arayın.\n"
)

CLEAN_TECHNICAL = (
    "The scanner reads each file as UTF-8 and converts Windows line endings to LF. It then blanks fenced "
    "code and YAML frontmatter so that reported line numbers match the original file. Each rule returns "
    "the line number, the matched text and a short fix. The command exits with status 1 when it reports "
    "a finding and with status 2 when a file cannot be read.\n"
)

GEMINI_STYLE = (
    "## 1. Discourse and Communication Principles\n"
    "\n"
    "* **Direct Answer on First Line:** Provide the answer.\n"
    "* **Scope Control:** Keep the reply to what was asked.\n"
)

# rule id -> (positive text, negative text). Every positive must raise the rule (default options);
# every negative must not.
RULE_CASES = {
    "1.1": ("The bridge stands as a testament to local engineering.",
            "The bridge is 40 metres long and opened in 1911."),
    "1.2": ("The band was featured in several national magazines.",
            "The band recorded two albums in 2019."),
    "1.3": ("The town hosts a fair each spring, highlighting its farming roots.",
            "The town hosts a fair each spring. Farmers sell produce there."),
    "1.4": ("The hotel offers breathtaking views of the bay.",
            "The hotel has 40 rooms and a car park."),
    "1.5": ("Experts argue that the new route will cut delays.",
            "A 2021 council report found the new route cut delays by 8%."),
    "1.6": ("Despite its popularity, the park faces several challenges.",
            "The park lost its funding in 2020 and closed two trails."),
    "1.7": ("Urban beekeeping refers to keeping bee colonies in cities. It is popular in Paris.",
            "Urban beekeeping is keeping bee colonies in cities. It is popular in Paris."),
    "1.8": ("## Impact and legacy\n\nThe mill closed in 1980.",
            "## Effect on river traffic\n\nThe mill closed in 1980."),
    "2.1": ("We delve into the numbers below.",
            "This step is crucial for the build."),
    "2.2": ("The old station functions as a library today.",
            "The old station is a library today."),
    "2.3": ("He was associated with the reform movement.",
            "He led the reform movement from 1901."),
    "2.4": ("It's not just a tool, it's a workflow.",
            "It is a tool for tracking invoices."),
    "2.5": ("Our platform is fast, reliable, and secure.",
            "The tool supports Linux, macOS, and Windows."),
    "2.6": ("The singer released an album. The artist toured Europe. The performer retired in 2010.",
            "The singer released an album. The singer toured Europe. The singer retired in 2010."),
    "3.1": ("## Writing Clear And Useful Documentation\n\nText.",
            "## Writing clear and useful documentation\n\nText."),
    "3.2": ("The **parser**, the **cache** and the **writer** all run in one process.",
            "The **parser** and the **cache** run in one process."),
    "3.3": ("- **Speed:** it is quick.\n- **Safety:** it is checked.\n",
            "- Speed: it is quick.\n- Safety: it is checked.\n"),
    "3.4": ("The build passed — the deploy did not.",
            "The build passed; the deploy ran from 2010–2020 with --verbose set."),
    "3.5": ("## 🚀 Launch plan\n\nWe ship on Monday.",
            "## Launch plan\n\nWe ship on Monday."),
    "3.6": ("| Name | Size |\n|---|---|\n| a | 1 |\n| b | 2 |\n",
            "| Name | Size | Owner |\n|---|---|---|\n| a | 1 | x |\n| b | 2 | y |\n"),
    "3.7": ("It’s ready. It's shipped.",
            "It's ready. It's shipped."),
    "3.8": ("Intro.\n\n---\n\n## One\n\nA.\n\n---\n\n## Two\n\nB.\n\n---\n\n## Three\n\nC.\n",
            "Intro.\n\n---\n\n## One\n\nA.\n\n## Two\n\nB.\n\n---\n\n## Three\n\nC.\n"),
    "4.1": ("I hope this helps with your migration.",
            "The patch helps the parser recover from errors."),
    "4.2": ("As of my last knowledge cutoff, the library was unmaintained.",
            "As of version 2.0, the library is unmaintained."),
    "4.3": ("Contact [Your Name] at INSERT_URL before 2024-XX-XX.",
            "Read the [Link](https://example.com/docs) or the [guide][URL].\n\n[URL]: https://example.com\n"),
    "5.1": ("It's important to note that the cache is local.",
            "The cache is local."),
    "5.2": ("The trial ran for a year.\n\nIn conclusion, the plan worked.",
            "The trial ran for a year.\n\nOverall cost fell by 10%."),
    "6.1": ("Honestly? The plan failed on day one.",
            "The plan failed on day one, honestly."),
    "6.2": ("Let's dive into the details.",
            "Divers go into the lake at dawn."),
    "6.3": ("Data is the currency of modern business.",
            "The euro is the currency used in France."),
    "6.4": ("No templates. No defaults. No safety.",
            "We removed the templates because they hid errors. Defaults were dropped for the same reason."),
    "6.5": ("This is VERY VERY IMPORTANT news.",
            "The spec says clients MUST NOT retry."),
    "6.6": ("The dashboard understands your goals.",
            "The dashboard shows weekly totals."),
    "TR-1": ("Kahve bir içecek değil, bir deneyimdir.",
             "Hava soğuk değil, sıcak."),
    "TR-2": ("Ekip, projede kritik bir rol oynamaktadır.",
             "Ekip, projeyi iki haftada bitirdi."),
    "TR-3": ("Menümüz geniş bir yelpazede tatlı sunuyor.",
             "Menümüzde on iki çeşit tatlı var."),
    "TR-4": ("Festival her yıl binlerce kişiyi ağırlıyor, kentin mirasının önemini vurgulayarak.",
             "Festival her yıl binlerce kişiyi ağırlıyor."),
    "TR-5": ("Proje bitti.\n\nSonuç olarak, bölge daha güvenli.",
             "Proje bitti.\n\nSonuçta bölge daha güvenli oldu ve herkes memnun."),
    "TR-6": ("Kurulum adımları yukarıda. Umarım bu yardımcı olur.",
             "Kurulum adımları yukarıda. Sorunda hata kaydını gönderin."),
}


def rule_ids(text: str, **options) -> set:
    return {f.rule_id for f in csm.scan_text(text, **options).findings}


def run_cli(*args: str, stdin: str = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    return subprocess.run([sys.executable, str(SCRIPT), *args], input=stdin, capture_output=True,
                          text=True, encoding="utf-8", env=env, timeout=60)


class TestRuleCatalogue(unittest.TestCase):
    def test_every_rule_has_a_case(self):
        self.assertEqual(set(RULE_CASES), set(csm.RULES))

    def test_positive_examples_fire(self):
        for rule_id, (positive, _) in RULE_CASES.items():
            with self.subTest(rule=rule_id):
                self.assertIn(rule_id, rule_ids(positive))

    def test_negative_examples_stay_clean(self):
        for rule_id, (_, negative) in RULE_CASES.items():
            with self.subTest(rule=rule_id):
                self.assertNotIn(rule_id, rule_ids(negative))

    def test_findings_carry_every_field(self):
        finding = csm.scan_text("I hope this helps.").findings[0]
        self.assertEqual(
            list(dataclasses.asdict(finding)),
            ["rule_id", "category", "severity", "line_number", "excerpt", "matched_span", "fix_hint"])
        self.assertEqual(finding.line_number, 1)
        self.assertEqual(finding.matched_span, "I hope this helps")
        self.assertTrue(finding.fix_hint)


class TestSpecificRules(unittest.TestCase):
    def test_title_defining_lead_is_case_sensitive(self):
        self.assertIn("1.7", rule_ids("Urban beekeeping refers to keeping bees in cities."))
        self.assertNotIn("1.7", rule_ids("the term urban beekeeping refers to keeping bees in cities."))

    def test_title_defining_lead_only_in_first_three_sentences(self):
        text = "Bees matter. Hives are small. Cities have roofs. Urban beekeeping refers to hives on roofs."
        self.assertNotIn("1.7", rule_ids(text))

    def test_all_caps_run_is_case_sensitive(self):
        self.assertIn("6.5", rule_ids("STOP RIGHT THERE NOW, please."))
        self.assertNotIn("6.5", rule_ids("Stop right there now, please."))

    def test_scare_quotes_need_a_cluster(self):
        self.assertIn("6.5", rule_ids('The "solution" was a "fix" for "users" in the end.'))
        self.assertNotIn("6.5", rule_ids('The "solution" was simple.'))
        self.assertIn("6.5", rule_ids('The "solution" was simple.', strict=True))

    def test_ai_vocabulary_clusters(self):
        self.assertNotIn("2.1", rule_ids("This step is crucial for the build."))
        self.assertIn("2.1", rule_ids("This step is crucial for the build.", strict=True))
        self.assertIn("2.1", rule_ids("A vibrant and intricate design."))
        self.assertIn("2.1", rule_ids("Additionally, the tool logs errors."))
        self.assertNotIn("2.1", rule_ids("The tool additionally logs errors."))

    def test_rather_than_needs_repetition(self):
        self.assertNotIn("2.4", rule_ids("Use a list rather than a set."))
        self.assertIn("2.4", rule_ids("Use a list rather than a set. Pick speed rather than size."))
        self.assertIn("2.4", rule_ids("Use a list rather than a set.", strict=True))

    def test_rule_of_three_repetition(self):
        text = "We bake bread, cakes and pies. We sell tea, coffee and juice. We open Monday, Tuesday and Friday."
        self.assertIn("2.5", rule_ids(text))
        self.assertNotIn("2.5", rule_ids("We bake bread, cakes and pies."))

    def test_placeholder_rule_is_not_triggered_by_real_links(self):
        self.assertNotIn("4.3", rule_ids("See [Link](https://example.com)."))
        self.assertIn("4.3", rule_ids("See [Link] for details."))

    def test_copula_duplicate_of_significance_is_merged(self):
        ids = [f.rule_id for f in csm.scan_text("The tower stands as a symbol.").findings]
        self.assertIn("1.1", ids)
        self.assertNotIn("2.2", ids)

    def test_overlapping_phrases_of_one_rule_merge(self):
        spans = [f.matched_span for f in csm.scan_text("Nestled in the heart of the city.").findings
                 if f.rule_id == "1.4"]
        self.assertEqual(spans, ["Nestled in the heart of"])


class TestPositiveFixtures(unittest.TestCase):
    def test_cafe_example(self):
        report = csm.scan_text(CAFE)
        self.assertEqual(report.language, "en")
        ids = {f.rule_id for f in report.findings}
        self.assertTrue({"1.1", "1.3", "1.4", "2.1", "2.4", "3.4", "4.2", "5.1"} <= ids, ids)
        by_rule = {(f.rule_id, f.matched_span) for f in report.findings}
        self.assertIn(("1.4", "Nestled in the heart of"), by_rule)
        self.assertIn(("2.4", "it's not just a coffee shop, it's"), by_rule)
        self.assertIn(("4.2", "not widely documented"), by_rule)
        self.assertEqual({f.line_number for f in report.findings if f.rule_id == "3.4"}, {2})
        self.assertGreater(report.density, 100)

    def test_turkish_example(self):
        report = csm.scan_text(TURKISH)
        self.assertEqual(report.language, "tr")
        ids = {f.rule_id for f in report.findings}
        self.assertEqual({"TR-1", "TR-2", "TR-3", "TR-4", "TR-5", "TR-6"}, ids & {r for r in csm.RULES if r.startswith("TR")})
        self.assertFalse({r for r in ids if not r.startswith("TR")}, "English-only rules must not run on Turkish text")

    def test_turkish_negative_parallelism_is_a_real_pattern(self):
        spans = [f.matched_span for f in csm.scan_text("Kahve bir içecek değil, bir deneyimdir.").findings
                 if f.rule_id == "TR-1"]
        self.assertEqual(spans, ["içecek değil, bir deneyimdir"])
        self.assertIn("TR-1", rule_ids("Bu bir ürün değil, bir yaşam tarzıdır."))
        self.assertIn("TR-1", rule_ids("Bu bir kütüphane değil, API'dir."))
        self.assertNotIn("TR-1", rule_ids("X değil, bir Y'dir.", lang="en"))

    def test_turkish_rules_respect_language_flag(self):
        self.assertFalse({r for r in rule_ids(TURKISH, lang="en") if r.startswith("TR")})
        self.assertTrue({r for r in rule_ids(TURKISH, lang="tr") if r.startswith("TR")})


class TestNegativeFixtures(unittest.TestCase):
    def test_clean_technical_paragraph(self):
        self.assertEqual(csm.scan_text(CLEAN_TECHNICAL).findings, [])
        self.assertEqual(csm.scan_text(CLEAN_TECHNICAL, profile="technical").findings, [])

    def test_clean_turkish_paragraph(self):
        report = csm.scan_text(TURKISH_CLEAN)
        self.assertEqual(report.language, "tr")
        self.assertEqual(report.findings, [])


class TestMasking(unittest.TestCase):
    def test_fenced_code_is_masked(self):
        text = ("Intro line.\n\n```text\nI hope this helps — it stands as a testament.\n```\n\n"
                "~~~\nCertainly! Let's dive in.\n~~~\n")
        self.assertEqual(csm.scan_text(text).findings, [])

    def test_inline_code_is_masked(self):
        self.assertEqual(csm.scan_text("Run `I hope this helps` and `stands as a testament` here.").findings, [])

    def test_frontmatter_is_masked(self):
        text = "---\ntitle: I hope this helps\ndescription: Certainly! Stands as a testament — yes.\n---\nPlain body.\n"
        self.assertEqual(csm.scan_text(text).findings, [])

    def test_blockquote_is_masked(self):
        self.assertEqual(csm.scan_text("> Certainly! I hope this helps — it stands as a testament.\n").findings, [])

    def test_long_quotation_is_exempt_from_content_rules(self):
        text = 'The mayor said "this bridge stands as a testament to our town — truly" at the opening.'
        self.assertEqual(csm.scan_text(text).findings, [])
        curly = "The mayor said “this bridge stands as a testament to our town” at the opening."
        self.assertNotIn("1.1", rule_ids(curly))

    def test_short_quotation_stays_visible(self):
        self.assertIn("1.1", rule_ids('Call it "stands as a" if you like.'))

    def test_line_numbers_survive_masking(self):
        text = ("---\ntitle: x\n---\n\n```python\nprint('a')\nprint('b')\n```\n\n> quoted line\n\n"
                "Line eleven is fine. I hope this helps.\n")
        findings = csm.scan_text(text).findings
        self.assertEqual([(f.rule_id, f.line_number) for f in findings], [("4.1", 12)])
        masked = csm.mask_markdown(text)
        self.assertEqual(masked.count("\n"), text.count("\n"))
        self.assertEqual([len(line) for line in masked.split("\n")], [len(line) for line in text.split("\n")])

    def test_html_is_converted_with_source_line_numbers(self):
        html = ("<!doctype html>\n<html><head><title>I hope this helps</title>\n<style>p{}</style></head>\n<body>\n"
                "<h2>Impact and legacy</h2>\n<p>Our café is <b>nestled in</b> the old town.</p>\n"
                "<pre>stands as a testament</pre>\n<script>var s = 'Certainly!';</script>\n"
                "<blockquote>Great question!</blockquote>\n"
                "<ul><li>&#x1F680; Fast</li><li>Slow</li></ul>\n</body></html>\n")
        report = csm.scan_text(html, kind="html")
        got = {(f.rule_id, f.line_number) for f in report.findings}
        self.assertEqual(got, {("1.8", 5), ("1.4", 6), ("3.5", 10)})


class TestSentenceSplitter(unittest.TestCase):
    def test_abbreviations_do_not_split(self):
        text = ("Mr. Smith met Dr. Jones and Mrs. Lee at St. Paul's. Prof. Kaya, e.g. the chair, i.e. the host, "
                "spoke vs. the board etc. about Fig. 2 and No. 5. It ended.")
        self.assertEqual(csm.split_sentences(text), [
            "Mr. Smith met Dr. Jones and Mrs. Lee at St. Paul's.",
            "Prof. Kaya, e.g. the chair, i.e. the host, spoke vs. the board etc. about Fig. 2 and No. 5.",
            "It ended.",
        ])

    def test_numbers_and_versions_do_not_split(self):
        self.assertEqual(csm.split_sentences("Use v2.0 with Python 3.14 and spec 1.1 here. Then stop."),
                         ["Use v2.0 with Python 3.14 and spec 1.1 here.", "Then stop."])

    def test_terminal_punctuation_splits(self):
        self.assertEqual(csm.split_sentences("Honestly? It failed! No. Stop."),
                         ["Honestly?", "It failed!", "No.", "Stop."])


class TestProfiles(unittest.TestCase):
    def test_prose_flags_gemini_style_markdown(self):
        ids = rule_ids(GEMINI_STYLE)
        self.assertIn("3.1", ids)
        self.assertIn("3.3", ids)

    def test_technical_does_not_flag_gemini_style_markdown(self):
        ids = rule_ids(GEMINI_STYLE, profile="technical")
        self.assertNotIn("3.1", ids)
        self.assertNotIn("3.3", ids)

    def test_technical_disables_structure_rules_only(self):
        for rule_id in ("3.1", "3.2", "3.3", "3.5", "3.6", "3.8"):
            with self.subTest(rule=rule_id):
                self.assertNotIn(rule_id, rule_ids(RULE_CASES[rule_id][0], profile="technical"))
        for rule_id in ("1.1", "2.4", "4.1", "3.4", "6.4", "TR-1", "TR-6"):
            with self.subTest(rule=rule_id):
                self.assertIn(rule_id, rule_ids(RULE_CASES[rule_id][0], profile="technical"))

    def test_technical_makes_in_order_to_cluster_only(self):
        single = "We cache the index in order to save time."
        self.assertIn("5.1", rule_ids(single))
        self.assertNotIn("5.1", rule_ids(single, profile="technical"))
        self.assertIn("5.1", rule_ids(single, profile="technical", strict=True))
        cluster = "We cache the index in order to save time. Results may vary by disk."
        self.assertIn("5.1", rule_ids(cluster, profile="technical"))


class TestEmDashSource(unittest.TestCase):
    SINGLE = "The build passed — the deploy did not."
    CLUSTER = "The build passed — the deploy did not — and the log was empty."

    def test_agent_mode_flags_a_single_em_dash(self):
        findings = [f for f in csm.scan_text(self.SINGLE).findings if f.rule_id == "3.4"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("R-02", findings[0].fix_hint)

    def test_agent_mode_flags_spaced_double_hyphen(self):
        self.assertIn("3.4", rule_ids("The build passed -- the deploy did not."))

    def test_human_mode_ignores_a_single_em_dash(self):
        self.assertNotIn("3.4", rule_ids(self.SINGLE, source="human"))
        self.assertIn("3.4", rule_ids(self.SINGLE, source="human", strict=True))

    def test_human_mode_flags_a_cluster(self):
        findings = [f for f in csm.scan_text(self.CLUSTER, source="human").findings if f.rule_id == "3.4"]
        self.assertEqual(len(findings), 2)
        self.assertIn("do not rewrite deliberate style silently", findings[0].fix_hint)

    def test_human_mode_density_threshold(self):
        paragraphs = "\n\n".join(f"Part {n} ended — then the next began." for n in range(3))
        self.assertIn("3.4", rule_ids(paragraphs, source="human"))
        self.assertNotIn("3.4", rule_ids("\n\n".join(paragraphs.split("\n\n")[:2]), source="human"))


class TestCommandLine(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="agy_markers_")
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name: str, text: str) -> Path:
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_exit_code_clean(self):
        result = run_cli(str(self.write("clean.md", CLEAN_TECHNICAL)))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("No synthetic markers found.", result.stdout)

    def test_exit_code_findings(self):
        result = run_cli(str(self.write("cafe.md", CAFE)))
        self.assertEqual(result.returncode, 1)
        self.assertIn("[1.4]", result.stdout)
        self.assertIn('Matched: "Nestled in the heart of"', result.stdout)

    def test_exit_code_errors(self):
        self.assertEqual(run_cli(str(self.tmp / "missing.md")).returncode, 2)
        self.assertEqual(run_cli("--profile", "bogus", str(self.write("a.md", "x"))).returncode, 2)
        self.assertEqual(run_cli("--json", "--summary", str(self.write("b.md", "x"))).returncode, 2)
        bad = self.tmp / "bad.md"
        bad.write_bytes(b"\xff\xfe\xfa not utf-8")
        self.assertEqual(run_cli(str(bad)).returncode, 2)

    def test_directory_scan_filters_extensions(self):
        self.write("a.md", CAFE)
        self.write("b.txt", CLEAN_TECHNICAL)
        self.write("c.py", "I hope this helps")
        result = run_cli("--json", str(self.tmp))
        data = json.loads(result.stdout)
        self.assertEqual(sorted(Path(f["path"]).name for f in data["files"]), ["a.md", "b.txt"])

    def test_stdin(self):
        result = run_cli("-", stdin=CAFE)
        self.assertEqual(result.returncode, 1)
        self.assertIn("=== <stdin>", result.stdout)
        self.assertEqual(run_cli("-", stdin=CLEAN_TECHNICAL).returncode, 0)

    def test_json_schema(self):
        result = run_cli("--json", "-", stdin=CAFE)
        data = json.loads(result.stdout)
        self.assertEqual(set(data), {"files", "total_findings"})
        self.assertEqual(len(data["files"]), 1)
        entry = data["files"][0]
        self.assertEqual(set(entry), {"path", "words", "language", "density", "findings"})
        self.assertEqual(entry["path"], "<stdin>")
        self.assertEqual(entry["language"], "en")
        self.assertIsInstance(entry["words"], int)
        self.assertIsInstance(entry["density"], float)
        self.assertEqual(data["total_findings"], len(entry["findings"]))
        for finding in entry["findings"]:
            self.assertEqual(set(finding), {"rule_id", "category", "severity", "line_number", "excerpt",
                                            "matched_span", "fix_hint"})
            self.assertIsInstance(finding["line_number"], int)

    def test_summary(self):
        result = run_cli("--summary", "-", stdin=CAFE)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Status: FAIL (Action Required)", result.stdout)
        self.assertIn("flags / 1,000 words", result.stdout)
        self.assertIn("PASS", run_cli("--summary", "-", stdin=CLEAN_TECHNICAL).stdout)

    def test_flags_reach_the_scanner(self):
        self.assertEqual(run_cli("--source", "human", "-", stdin="The build passed — then it failed.").returncode, 0)
        self.assertEqual(run_cli("--profile", "technical", "-", stdin=GEMINI_STYLE).returncode, 0)
        self.assertEqual(run_cli("--profile", "prose", "-", stdin=GEMINI_STYLE).returncode, 1)
        self.assertEqual(run_cli("--lang", "en", "-", stdin=TURKISH).returncode, 0)
        self.assertEqual(run_cli("--strict", "-", stdin="This step is crucial.").returncode, 1)


if __name__ == "__main__":
    unittest.main()
