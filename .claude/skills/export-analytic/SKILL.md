---
name: export-analytic
description: Write the red-side handoff for one rule - its KQL, each clause on its own line, the tables it may use, and the variants found so far. Use when the user wants to hand a rule to the red side or review it by clause.
---

# Export analytic

This repo's version of CCCS's `/export-analytic`. The purple loop sends this same handoff to the red-side model.

Input: a rule file, or a pull request number (use the rule file that pull request adds or changes).

1. If given a pull request, check out its branch:
   `az repos pr checkout --id <PR>`
2. Write the handoff:
   ```bash
   python3 -m scripts.handoff detections/<folder>/<rule id>.yaml --out work/<rule id>.handoff.md
   ```
3. Show the user the clauses and the known variants, and point out any clause that depends on one exact
   string (those are where cosmetic variants slip through).

The handoff is plain text with no tenant data, so it's safe to share with the red side.
