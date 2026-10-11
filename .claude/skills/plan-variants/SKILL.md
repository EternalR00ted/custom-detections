---
name: plan-variants
description: Map a rule's red-side variants to CCCS tiers and to existing Atomic Red Team tests, and propose upstream tests a person can allowlist. Use when a rule has variants the lab can't test yet. Never writes attack code.
---

# Plan variants

This repo's replacement for CCCS's `/poc-cpp`. CCCS's red agent wrote its own proof-of-concept code.
This repo never does, not even for the lab. This skill only finds tests that already exist.

Input: a rule file or pull request number.

1. Read the rule's `metadata.purple_loop.variants` and its `lab_tests`.
2. Read `config/atomics.yaml`: the allowlisted tests, each with a tier.
3. Build a table: tier, variant, covered by an allowlisted test (which one) or not covered.
4. For variants not covered, look for an existing upstream Atomic Red Team test at the commit pinned in
   `config/atomics.yaml`: read `atomics/Indexes/Indexes-CSV/windows-index.csv` from
   `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/<commit>/` and match on technique and behavior.
   Only propose tests whose executor is `powershell` or `command_prompt` and that have no dependencies;
   the lab runs nothing else.
5. For each proposal, give the GUID, the test name, the tier it would cover, and what it does in one sentence.
   Tell the user how to allowlist it in its own pull request, with the file's SHA-256:
   ```bash
   curl -sL https://raw.githubusercontent.com/redcanaryco/atomic-red-team/<commit>/atomics/<T>/<T>.yaml | shasum -a 256
   ```
6. A tier no test covers stays described in words in the tier table. Say so plainly.

Never write, modify or suggest attack code, payloads or commands beyond what the pinned upstream tests contain.
Never edit `config/atomics.yaml` yourself; a person adds tests.
