---
name: purple-loop
description: Walk one AI-drafted rule through the full CCCS purple loop with the user - export the handoff, plan variants, detonate, verify by tier, decide together, harden, and record the result. Use when the user wants to take a rule pull request from draft to a decision.
---

# Purple loop

This repo's version of CCCS's `/purple-loop`. You drive the loop; the user decides. Ask before you change,
commit or push anything, and never approve, complete or abandon a pull request yourself.

Input: a pull request number.

1. **Check auth.** Run `/ensure-auth`. Stop if anything fails.
2. **Read the pull request.** `az repos pr show --id <PR>`: the source, the evidence quotes, the tier table
   and the jury votes in the description and the first comment. Summarize in five lines.
3. **Export.** Run `/export-analytic` for the rule.
4. **Plan variants.** Run `/plan-variants`. If a tier has no allowlisted test, say so; don't invent one.
5. **Production check.** Run `/run-analytic`. If it's `NOISY`, stop and help the user review hits in
   Advanced hunting before anything else.
6. **Detonate.** If the rule lists lab tests, run `/detonate` and wait for the user to approve.
7. **Verify.** Run `/verify-evasion`.
8. **Decide with the user.** Lay out: what the rule catches (lab-proven), what it misses (red side,
   jury, lab), and its noise. Offer three choices: approve as is, harden, or deny with a lesson.
9. **Harden** (if chosen): propose the exact KQL change, wait for a yes, edit the rule on the pull
   request branch, run `python3 -m scripts.rules detections`, commit, push, and let Rule checks run again.
   Go back to step 5.
10. **Record.** Post a short summary on the pull request: rounds, what changed, what's still a gap:
    `az repos pr update --id <PR> --description "<existing description plus a 'Purple loop with <user>' section>"`
    only if the description has room (4,000 characters); otherwise tell the user to paste it as a comment.
11. **Deny** (if chosen): give the user the deny block from Step 11 of `docs/setup.md` with the lesson filled in.
