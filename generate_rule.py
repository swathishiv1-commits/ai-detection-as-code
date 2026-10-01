"""
generate_rule.py

CLI entrypoint for the full AI Detection-as-Code pipeline:

    CTI text  →  LLM rule generator  →  validate  →  Sigma YAML  →  test

Usage:
    python generate_rule.py --text "..." --logsource windows_sysmon
    python generate_rule.py --url  https://example.com/threat-report --logsource aws_cloudtrail
    python generate_rule.py --file /path/to/report.txt --logsource aws_cloudtrail
    python generate_rule.py --text "..." --logsource aws_cloudtrail --no-test
    python generate_rule.py --text "..." --logsource aws_cloudtrail --datadog-payload
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Lazy imports so --help still works even without dependencies installed
def _import_pipeline():
    from generator.ingestion import ingest
    from generator.llm_rule_generator import generate_rule
    from converters.json_to_sigma import render_sigma_yaml, write_rule
    from converters.sigma_to_datadog import to_datadog_rule
    from validator.sigma_validator import validate_rule_dict, validate_with_pysigma
    from test_corpus.test_runner import run_test, _resolve_corpus
    return ingest, generate_rule, render_sigma_yaml, write_rule, to_datadog_rule, validate_rule_dict, validate_with_pysigma, run_test, _resolve_corpus


LOGSOURCE_MAP = {
    "aws_cloudtrail": {"product": "aws", "service": "cloudtrail"},
    "aws":            {"product": "aws", "service": "cloudtrail"},
    "windows_sysmon": {"product": "windows", "category": "process_creation"},
    "windows":        {"product": "windows", "category": "process_creation"},
}

OUTPUT_DIRS = {
    "aws_cloudtrail": "rules/cloud_aws",
    "aws":            "rules/cloud_aws",
    "windows_sysmon": "rules/windows",
    "windows":        "rules/windows",
}


def _banner(msg: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {msg}")
    print(f"{'─' * 60}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a Sigma detection rule from CTI text using an LLM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # From pasted text, targeting Windows logs
  python generate_rule.py \\
    --text "Ransomware deleted shadow copies using vssadmin then encrypted files." \\
    --logsource windows

  # From a URL, targeting AWS CloudTrail
  python generate_rule.py \\
    --url https://securelist.com/some-apt-report \\
    --logsource aws_cloudtrail

  # Generate without running the test (faster iteration)
  python generate_rule.py --text "..." --logsource windows --no-test

  # Also emit a Datadog Cloud SIEM rule payload
  python generate_rule.py --text "..." --logsource windows --datadog-payload
        """,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="CTI text pasted directly")
    source.add_argument("--url",  help="URL of a threat report / blog post")
    source.add_argument("--file", help="Path to a local CTI report file")

    parser.add_argument(
        "--logsource",
        required=True,
        choices=list(LOGSOURCE_MAP),
        help="Log source hint to steer the LLM toward the right field names",
    )
    parser.add_argument("--no-test",         action="store_true", help="Skip test corpus evaluation")
    parser.add_argument("--no-write",        action="store_true", help="Don't write YAML to disk, just print it")
    parser.add_argument("--datadog-payload", action="store_true", help="Also emit a Datadog Cloud SIEM rule JSON")
    parser.add_argument("--out-dir",         help="Override output directory for the generated rule")

    args = parser.parse_args()

    (ingest, generate_rule, render_sigma_yaml, write_rule,
     to_datadog_rule, validate_rule_dict, validate_with_pysigma,
     run_test, _resolve_corpus) = _import_pipeline()

    # ── 1. Ingest ──────────────────────────────────────────────────────────
    _banner("Step 1 / 4 — Ingesting CTI text")
    try:
        cti_text = ingest(text=args.text, url=args.url, file=args.file)
    except Exception as exc:
        print(f"❌ Ingestion failed: {exc}")
        return 1
    print(f"  Ingested {len(cti_text):,} characters.")

    # ── 2. Generate ────────────────────────────────────────────────────────
    _banner("Step 2 / 4 — Generating rule JSON via LLM")
    try:
        rule = generate_rule(cti_text, logsource_hint=args.logsource)
    except Exception as exc:
        print(f"❌ Rule generation failed: {exc}")
        return 1

    # Patch the logsource with the hint to avoid the model making up product names
    rule.setdefault("logsource", {}).update(LOGSOURCE_MAP[args.logsource])

    print(f"  Rule title: {rule.get('title', '<unknown>')}")
    print(f"  MITRE tags: {', '.join(rule.get('tags', [])) or 'none'}")
    print(f"  Level:      {rule.get('level', '?')}")
    if rule.get("notes"):
        print(f"  Notes:      {rule['notes']}")

    # ── 3. Validate ────────────────────────────────────────────────────────
    _banner("Step 3 / 4 — Validating rule")
    structural = validate_rule_dict(rule)
    print(structural)

    if not structural.valid:
        print("\n❌ Rule failed structural validation — not writing to disk.")
        print("   Fix the errors above or rerun to regenerate from the LLM.")
        return 1

    sigma_yaml = render_sigma_yaml(rule)
    pysigma_result = validate_with_pysigma(sigma_yaml)
    if pysigma_result.warnings or not pysigma_result.valid:
        print(pysigma_result)
    if not pysigma_result.valid:
        print("\n⚠️  pySigma validation failed. Proceeding anyway — review the YAML manually.")

    # Print rendered YAML
    print("\n── Generated Sigma YAML ──────────────────────────────────────")
    print(sigma_yaml)

    # Write to disk
    if not args.no_write:
        out_dir = args.out_dir or OUTPUT_DIRS.get(args.logsource, "rules")
        written_path = write_rule(rule, out_dir)
        print(f"  ✅ Written to: {written_path}")

    # Optional Datadog payload
    if args.datadog_payload:
        print("\n── Datadog Cloud SIEM rule payload ───────────────────────────")
        dd_payload = to_datadog_rule(rule)
        print(json.dumps(dd_payload, indent=2))

    # ── 4. Test ────────────────────────────────────────────────────────────
    if not args.no_test:
        _banner("Step 4 / 4 — Running test corpus evaluation")
        corpus_path = _resolve_corpus(rule["logsource"])
        if corpus_path is None:
            print(
                "  ⚠️  No synthetic log corpus found for this logsource. "
                "Skipping test.\n"
                "  To add one, create a JSON file in test_corpus/synthetic_logs/ "
                "and add a routing entry in test_corpus/test_runner.py."
            )
        else:
            result = run_test(rule, corpus_path=corpus_path, verbose=True)
            if result.tp == 0 and result.fn > 0:
                print("\n❌ Rule scored zero true positives — revisit the detection logic.")
                return 1
    else:
        print("\n  (test step skipped via --no-test)")

    print("\n✅ Pipeline complete.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
