---
name: verify-evasion
description: Read a rule's lab detonation results by CCCS tier and compare them with the red side's tier table and the model jury. Use after a Lab detonation run, or when the user asks which variants a rule really catches.
---

# Verify evasion

This repo's version of CCCS's `/verify-evasion`.

Input: a pull request number.

1. Read the newest `### Lab detonation results` comment and the rule file's `metadata.purple_loop.variants`
   and `metadata.jury` (check out the branch with `az repos pr checkout --id <PR>`).
2. Build one table: tier, test or variant, red side said caught, lab said caught, lab telemetry seen.
3. Call out disagreements:
   - Red side said caught, lab says NO with telemetry present: the rule's logic misses it. That's a real gap.
   - Lab says NO with no telemetry: the VM didn't record it. Not a rule problem; check the sensor.
   - A tier with no lab test: still only the red side's opinion. Say that.
4. If there's a real gap, describe the change to the KQL in words and ask the user whether to make it.
   Only edit the rule after they say yes, then let Rule checks run again.
