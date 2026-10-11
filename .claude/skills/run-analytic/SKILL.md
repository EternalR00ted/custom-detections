---
name: run-analytic
description: Re-run the production check (Rule checks) on a pull request and explain the result - static checks, compile, 3-day zero-hit check, red-side review and model jury. Use when the user asks whether a rule is noisy, why Rule checks failed, or to re-check a pull request.
---

# Run analytic

This repo's version of CCCS's `/run-analytic`. Hunting queries run in the Rule checks pipeline, not on
this computer, so results stay counts only.

Input: a pull request number. Ask for it if the user didn't give one.

1. Find the Rule checks evaluation and queue it again:
   ```bash
   az repos pr policy list --id <PR> --query "[?configuration.settings.displayName=='Rule checks'].evaluationId | [0]" -o tsv
   az repos pr policy queue --id <PR> --evaluation-id <evaluation id>
   ```
2. Wait for it: check `az repos pr policy list --id <PR> --query "[?configuration.settings.displayName=='Rule checks'].status | [0]" -o tsv`
   every 30 seconds until it isn't `queued` or `running`. Tell the user while you wait.
3. Read the newest comment that starts with `### Rule checks`:
   ```bash
   az devops invoke --area git --resource pullRequestThreads --route-parameters project=<project> repositoryId=<repo> pullRequestId=<PR> --api-version 7.1 --query "value[].comments[0].content" -o json
   ```
   Use the project and repo from `az devops configure --list` and `az repos show --repository <repo> --query name`.
4. Explain it in plain words:
   - Static or Sigma failures: the exact problem and the line to change.
   - Compile failures: Defender's error, and what it usually means.
   - `NOISY`: the rule hit real data in the last 3 days. The user must look at every hit in Advanced hunting.
     Only if every hit is a true positive, they add the label the comment names (`noise-reviewed-<commit>`).
     Never add that label yourself.
   - Red-side review and jury: which variants or findings matter, and which look wrong.

Never print or ask for hunting rows. The pipeline only reports counts, and that's on purpose.
