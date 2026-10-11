---
name: ensure-auth
description: Check that this computer can drive the detection pipeline - Azure CLI sign-in, the Azure DevOps extension and defaults, the service connections, variable group and pipelines. Use before any other skill in this repo, or when a command here fails with a sign-in error.
---

# Ensure auth

This repo's version of CCCS's `/ensure-trino-auth`. It only reads; it changes nothing.

Run each check, then give the user one table: check, result, and the fix for anything that failed.

1. `az account show --query "{user:user.name, tenant:tenantId, subscription:name}" -o table`
   - Fails: tell the user to run `az login`.
2. `az extension show --name azure-devops --query version -o tsv`
   - Missing: `az extension add --name azure-devops`.
3. `az devops configure --list`
   - Needs `organization` and `project`. If missing, ask the user for both and suggest
     `az devops configure --defaults organization=https://dev.azure.com/<org> project=<project>`.
4. `az devops service-endpoint list --query "[].{name:name, ready:isReady}" -o table`
   - Expect `detections-read`, `detections-detonate` and `detections-deploy`, all ready.
5. `az pipelines variable-group list --group-name detections --query "[0].variables" -o json`
   - Expect `COMPANY_NAME`, `LAB_RESOURCE_GROUP`, `LAB_VM`, and the secrets `ANTHROPIC_API_KEY`
     (required), `GEMINI_API_KEY`, `OPENAI_API_KEY` and `NIMBLE_API_KEY`. Never print secret values;
     their values show as null, which is fine. `SENTRY_DSN` is optional and plain; if it's missing,
     say Sentry tracing is off.
6. `az pipelines list --query "[].name" -o tsv`
   - Expect Rule checks, Draft rules, Lab detonation, Deploy rules and Shadow run.
7. `python3 -m unittest discover --buffer --start-directory tests --top-level-directory .`
   - If imports fail, suggest `python3 -m pip install -r requirements.txt` in a virtual environment.

If everything passes, say so in one line and suggest `/purple-loop <pull request number>`.
