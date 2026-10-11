---
name: detonate
description: Queue the Lab detonation check on a pull request, show the user the fire plan, and wait while they approve it in Azure DevOps. Use when the user wants to test a rule in the lab. Never approves anything itself.
---

# Detonate

This repo's version of CCCS's `/detonate-poc`. A person approves every detonation in Azure DevOps.
This skill never approves, and never runs anything on the lab VM directly.

Input: a pull request number.

1. Check the pull request only changes rule and Sigma files:
   `az repos pr show --id <PR> --query "{source:sourceRefName, title:title}"` and list the files with
   `git diff --name-only origin/main...<source branch>` after `git fetch`.
   If anything outside `detections/` or `sigma/` changed, stop and tell the user why: a detonation runs
   the branch's own pipeline and scripts.
2. Queue the check:
   ```bash
   az repos pr policy list --id <PR> --query "[?configuration.settings.displayName=='Lab detonation'].evaluationId | [0]" -o tsv
   az repos pr policy queue --id <PR> --evaluation-id <evaluation id>
   ```
3. Wait for the comment that starts with `### Fire plan (lab detonation)` (read threads the way
   `/run-analytic` does). Show the user the whole fire plan: target, every command and cleanup, tiers,
   pre-flight checks.
4. Tell the user exactly where to approve: Azure DevOps, Pipelines > Lab detonation > the waiting run >
   Review > Approve. Remind them to approve only if the fire plan matches what they expect.
5. Wait for the comment that starts with `### Lab detonation results` (up to an hour; the pipeline waits
   10 minutes for telemetry, then polls). Then hand off to `/verify-evasion`.
