# AI Detection-as-Code

Generate, validate, and test Sigma detection rules from threat intel using an LLM —
wired into a CI pipeline so every rule is tested before it merges.

## Why this exists

Detection engineering teams write rules by hand from CTI reports, which is slow and
inconsistent. This project uses an LLM as a **first-draft generator**, not a black box:
every generated rule passes through schema validation and a synthetic-log test corpus
before a human (or CI) signs off on it. The goal is to show AI accelerating detection
engineering without removing the validation discipline that makes detections trustworthy.

## Architecture

```
CTI report / ATT&CK technique text
            │
            ▼
   generator/ingestion.py        — clean raw text from a paste, file, or URL
            │
            ▼
   generator/llm_rule_generator.py — LLM call, forced structured JSON output
            │
            ▼
   converters/json_to_sigma.py   — render JSON → valid Sigma YAML (templated, not freeform LLM YAML)
            │
            ▼
   validator/sigma_validator.py  — schema validation (pySigma if installed, else local schema check)
            │
            ▼
   test_corpus/test_runner.py    — evaluate the rule's detection logic against synthetic logs
            │                       → precision / recall / TP / FP counts
            ▼
   .github/workflows/detection-ci.yml — runs validation + tests on every PR touching rules/
            │
            ▼ (stretch)
   converters/sigma_to_datadog.py — transpile a subset of Sigma rules to Datadog Cloud SIEM JSON
```

## Why an LLM doesn't write raw Sigma YAML directly

LLMs are unreliable at producing syntactically valid YAML with exactly correct Sigma
field names under arbitrary prompting. Instead, the LLM is constrained to emit a fixed
JSON schema (title, logsource, detection selections, condition, MITRE tags, etc.), and a
deterministic template renders that JSON into Sigma YAML. This makes failures easy to
catch (JSON schema validation) instead of debugging malformed YAML the model invented.

## Project layout

```
generator/
  ingestion.py            # pull CTI text from paste / file / URL
  llm_rule_generator.py    # calls Claude, returns structured rule JSON
  prompts/
    system_prompt.md       # the detection-engineer persona + output schema
    few_shot_examples.yaml  # hand-written CTI → rule JSON examples
converters/
  json_to_sigma.py         # JSON → Sigma YAML
  sigma_to_datadog.py       # Sigma → Datadog Cloud SIEM rule JSON (stretch goal, partial)
validator/
  sigma_validator.py        # schema + structural validation
  sigma_evaluator.py        # lightweight Sigma detection-logic evaluator for testing
test_corpus/
  synthetic_logs/            # synthetic AWS CloudTrail + Sysmon-style logs (benign + malicious)
  test_runner.py             # runs a rule's logic against the corpus, scores it
rules/                        # generated rules land here, organized by log source
.github/workflows/
  detection-ci.yml            # CI: validate + test every rule on PR
generate_rule.py               # CLI entrypoint tying the whole pipeline together
```

## Setup

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add your ANTHROPIC_API_KEY
```

## Usage

Generate a rule from a pasted CTI snippet:

```bash
python generate_rule.py --text "Attackers used valid cloud credentials obtained via \
phishing to call AWS STS AssumeRole from an unfamiliar geography, then enumerated S3 \
buckets across the account." --logsource aws_cloudtrail
```

Generate from a URL:

```bash
python generate_rule.py --url https://example.com/threat-report --logsource aws_cloudtrail
```

This will:
1. Ingest and clean the source text
2. Call the LLM to draft structured rule JSON
3. Render it to Sigma YAML in `rules/cloud_aws/`
4. Validate the rule
5. Run it against the matching synthetic log corpus and print precision/recall

## Testing an existing rule manually

```bash
python -m test_corpus.test_runner --rule rules/cloud_aws/unfamiliar_geo_assume_role.yml
```

## CI

Any PR that touches `rules/**` triggers `.github/workflows/detection-ci.yml`, which
validates every changed rule and runs it against the synthetic corpus, failing the
build if a rule doesn't parse or scores zero true positives against its own test logs.

## Roadmap / stretch goals

- [ ] `sigma_to_datadog.py`: full field-mapping coverage for Datadog Cloud SIEM detection rules
- [ ] Streamlit front end for live demos
- [ ] Expand synthetic corpus to GCP audit logs and Okta logs
- [ ] Confidence scoring on LLM-drafted rules based on historical FP rates of similar rules

## Notes on data

All logs in `test_corpus/` are synthetic, hand-generated for testing purposes — no real
production data or customer data is used anywhere in this repo.
