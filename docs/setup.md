# Setup guide

This takes you from an Azure subscription and an Azure DevOps organization to the full pipeline in the [README](../README.md): Nimble finds new threat reports on the live web, Claude drafts rules from them, Claude Fable attacks each rule, Gemini and an OpenAI model review it independently, a lab VM proves it, and you approve every detonation and every rule. Sentry traces every run.

The models plug in by API key: Anthropic, OpenAI, Gemini and Nimble. Sentry plugs in with a DSN. There's nothing to deploy for any of them. Microsoft's side is only what Defender needs: the lab VM, three app identities and the Azure DevOps project.

Every block runs in Azure Cloud Shell (Bash). Step 1 asks for your names once and saves them in `~/detections-lab.env`, so nothing below needs editing before you paste it.

## Before you start

- An Azure subscription where you're Owner, for the lab VM.
- Global Administrator in that subscription's tenant. Step 5 grants Microsoft Graph application permissions, which needs it.
- An Azure DevOps organization connected to the same Microsoft Entra tenant, where you're an organization owner or Project Collection Administrator.
- API keys (Step 3 says where to get each): Anthropic (required), and Gemini, OpenAI and Nimble (each optional, but each one adds a part of the pipeline). A Sentry DSN is optional too.
- A GitHub account for the public copy of the code (Step 14).
- Azure Cloud Shell in Bash (shell.azure.com) with storage attached, so `$HOME` survives. Cloud Shell closes after 20 minutes without input. It already has az, gh, git and Python.
- Each block runs inside `( ... )` with `set -euo pipefail`. An error stops that block without closing your shell.

Start Step 2 early. Defender for Endpoint can take hours to onboard a new machine the first time.

## Step 1. Sign in and choose names

This signs you in to Azure and GitHub, adds the Azure DevOps extension to the Azure CLI, asks five questions and saves the answers. Press Enter to take the default in brackets.

Azure uses a device-code sign-in on purpose. Cloud Shell's built-in sign-in can't get tokens for Azure DevOps, and Microsoft's documented fix is `az login --use-device-code`.

```bash
(
set -euo pipefail
az login --use-device-code
az extension add --name azure-devops --upgrade --only-show-errors
gh auth login --hostname github.com --git-protocol https --web
ask() {  # question, default: prints your answer, or the default if you just press Enter
  local answer
  read -r -p "$1${2:+ [$2]}: " answer
  echo "${answer:-$2}"
}
ADO_ORG="$(ask "Azure DevOps organization (the name in https://dev.azure.com/<name>)" "")"
[ -n "$ADO_ORG" ] || { echo "Type your Azure DevOps organization name and run this block again."; exit 1; }
ADO_PROJECT="$(ask "Name for the new Azure DevOps project and its repo" "custom-detections")"
GH_LOGIN="$(gh api user --jq .login)"
GH_OWNER="$(ask "GitHub account or organization for the public copy" "$GH_LOGIN")"
COMPANY_NAME="$(ask "Name in front of every rule title, like your company" "$ADO_ORG")"
LOCATION="$(ask "Azure region for the lab VM" "canadacentral")"
cat > ~/detections-lab.env <<EOF
# Written by Step 1 of the setup guide. Run Step 1 again to change a name.
export ADO_ORG=$(printf %q "$ADO_ORG")
export ADO_ORG_URL=$(printf %q "https://dev.azure.com/$ADO_ORG")
export ADO_PROJECT=$(printf %q "$ADO_PROJECT")
export REPO_NAME=$(printf %q "$ADO_PROJECT")
export REPO_DIR=$(printf %q "$HOME/$ADO_PROJECT")
export GH_REPO=$(printf %q "$GH_OWNER/$ADO_PROJECT")
export COMPANY_NAME=$(printf %q "$COMPANY_NAME")
export LOCATION=$(printf %q "$LOCATION")
export RG_LAB=rg-detections-lab
export VM_NAME=detonation-vm
export ADO_RESOURCE=499b84ac-1321-427f-aa17-267ca6975798
EOF
source ~/detections-lab.env
az devops configure --defaults organization="$ADO_ORG_URL"
echo "Saved to ~/detections-lab.env:"
grep '^export' ~/detections-lab.env
az account show --query "{subscription:name, tenant:tenantId, user:user.name}" -o table
echo "Projects you can see in $ADO_ORG:"
az devops project list --organization "$ADO_ORG_URL" --query "value[].name" -o tsv || {
  echo "This sign-in can't open $ADO_ORG_URL. Check the organization name, and that the organization is connected to this tenant (Organization settings > Microsoft Entra)."
  exit 1
}
)
```

If the wrong subscription shows, run `az account set --subscription "<name>"` and run the block again. If you ran an earlier version of this step, running it again is safe.

## Step 2. Lab VM with Defender for Endpoint

This builds one Windows Server VM and turns on Defender for Servers Plan 1 for that VM only, not the whole subscription. Plan 1 includes Defender for Endpoint, which fills the `Device*` advanced hunting tables the rules query. Turning on the subscription's Defender for Endpoint integration costs nothing by itself; billing comes from the plan on this one VM.

The VM gets no inbound rules at all and a public IP for outbound traffic only (Windows updates, the Defender sensor, and the pinned Atomic Red Team files). Nobody needs its password: the pipeline runs commands through Azure Run Command, which runs as SYSTEM. So the block makes a random password and never prints it.

```bash
(
set -euo pipefail
source ~/detections-lab.env
SUB_ID="$(az account show --query id -o tsv)"
az provider register --namespace Microsoft.Security -o none
az group create --name "$RG_LAB" --location "$LOCATION" -o none
VM_PASSWORD="$(openssl rand -base64 48 | tr -d '/+=' | cut -c1-24)Aa1!"
az vm create --resource-group "$RG_LAB" --name "$VM_NAME" \
  --image MicrosoftWindowsServer:WindowsServer:2022-datacenter-azure-edition:latest \
  --size Standard_B2ms --storage-sku StandardSSD_LRS \
  --admin-username labadmin --admin-password "$VM_PASSWORD" \
  --nsg-rule NONE --public-ip-sku Standard -o none
unset VM_PASSWORD
VM_ID="$(az vm show --resource-group "$RG_LAB" --name "$VM_NAME" --query id -o tsv)"
az rest --method put \
  --url "https://management.azure.com$VM_ID/providers/Microsoft.Security/pricings/virtualMachines?api-version=2024-01-01" \
  --body '{"properties":{"pricingTier":"Standard","subPlan":"P1"}}' -o none
az rest --method put \
  --url "https://management.azure.com/subscriptions/$SUB_ID/providers/Microsoft.Security/settings/WDATP?api-version=2022-05-01" \
  --body '{"kind":"DataExportSettings","properties":{"enabled":true}}' -o none
echo "Defender for Servers on $VM_NAME: $(az rest --method get \
  --url "https://management.azure.com$VM_ID/providers/Microsoft.Security/pricings/virtualMachines?api-version=2024-01-01" \
  --query "join(' ', [properties.pricingTier, properties.subPlan])" -o tsv)"
)
```

It should end with `Defender for Servers on detonation-vm: Standard P1`. If `az vm create` fails with `SkuNotAvailable`, that size is out of capacity in your region: change `--size` to another 2 vCPU, 8 GB size and run the block again. If it fails with `QuotaExceeded`, that VM family has no quota in your subscription, even when the regional total has room. Check with `az vm list-usage --location "$LOCATION" -o table` and pick a family with a limit above 0. On the first deploy, `Standard_B2ms` had no capacity in Canada Central and `Standard_D2as_v4` worked.

Defender for Cloud now installs the Defender for Endpoint extension by itself. Check as often as you like. Move on when `MDE.Windows` shows `Succeeded`:

```bash
(source ~/detections-lab.env && az vm extension list --resource-group "$RG_LAB" --vm-name "$VM_NAME" --query "[].{extension:name, state:provisioningState}" -o table)
```

Then prove the hunting tables see the VM, because every check in this pipeline depends on them. In the Defender portal (security.microsoft.com), open **Hunting > Advanced hunting** and run:

```kusto
DeviceInfo
| where DeviceName startswith "detonation-vm"
| summarize LastSeen = max(Timestamp) by DeviceName, DeviceId, OnboardingStatus
```

A row with `Onboarded` is your go signal. When you see it, add a nightly 03:00 UTC auto-shutdown as a backstop and deallocate the VM. From then on only the Lab detonation pipeline starts it.

```bash
(source ~/detections-lab.env && az vm auto-shutdown --resource-group "$RG_LAB" --name "$VM_NAME" --time 0300 -o none && az vm deallocate --resource-group "$RG_LAB" --name "$VM_NAME" --no-wait && echo "Auto-shutdown set. Deallocating $VM_NAME.")
```

## Step 3. Get your API keys

Each model family plugs in with one key. You'll paste them in Step 5, which checks each one and stores it as a secret pipeline variable. Don't paste a key into a chat, an email or a file in the repo.

| Key | Where to get it | What it does here | If you skip it |
|---|---|---|---|
| Anthropic (required) | console.anthropic.com > **API keys** > **Create key**. Add a few dollars of credit under **Billing**. | Claude Opus 5.5 writes and hardens rules, Claude Fable 5.1 attacks them, Claude Haiku 5.5 is the triage backup | Nothing drafts |
| Gemini | aistudio.google.com/apikey > **Create API key**. The free tier is enough. | Gemini screens articles and sits on the jury | Claude Haiku triages; the jury has one member |
| OpenAI | platform.openai.com > **API keys** > **Create new secret key**. Add a few dollars of credit under **Billing**. | gpt-6.1-sol sits on the jury | The jury has one member |
| Nimble | nimbleway.com, start the free trial, then copy the key from the dashboard | Searches the live web for new reports and extracts article text | The drafter reads the RSS feeds only |
| Sentry DSN | sentry.io, start the free trial, create a **Python** project, then copy its DSN (**Settings > Projects >** your project **> Client Keys (DSN)**) | Error monitoring, and a trace of every run with each model call as an AI agent span: role, model, tokens, time, failures | Nothing is sent to Sentry |

Two things to set while you're in the consoles:

1. A monthly spend limit in the Anthropic and OpenAI billing pages. A normal day here costs well under a dollar or two, so a small limit stops surprises.
2. A key name you'll recognize, like `custom-detections pipeline`, so you know what to revoke later.

If you created a Foundry resource from an earlier version of this guide, nothing uses it anymore. Delete it when you're ready with `az group delete --name rg-detections-ai`.

## Step 4. Azure DevOps project and parallel jobs

This creates a private project with a Git repo of the same name. Azure DevOps can't create new public projects anymore, so the open-source copy goes to GitHub in Step 14.

```bash
(
set -euo pipefail
source ~/detections-lab.env
if az devops project show --project "$ADO_PROJECT" --organization "$ADO_ORG_URL" -o none 2>/dev/null; then
  echo "Project $ADO_PROJECT already exists."
else
  az devops project create --name "$ADO_PROJECT" --organization "$ADO_ORG_URL" \
    --visibility private --source-control git \
    --description "Defender XDR custom detections as code, with an AI drafting pipeline" -o none
fi
az devops configure --defaults organization="$ADO_ORG_URL" project="$ADO_PROJECT"
az repos show --repository "$REPO_NAME" --query "{repo:name, url:webUrl}" -o table
)
```

Pipelines need one parallel job. Azure DevOps gives every organization one free Microsoft-hosted job (60 minutes per run, 1,800 minutes a month) once the organization's billing is linked to an Azure subscription. Linking billing doesn't charge anything by itself.

1. Open `https://dev.azure.com/<your organization>/_settings/billing`.
2. If it says **Set up billing**, select it and pick the same Azure subscription.
3. Open your project's **Project settings > Parallel jobs**. **Microsoft-hosted, Private projects** should show 1 free job.


## Step 5. Identities, service connections, keys and the variable group

Each pipeline signs in to Azure through a service connection that uses workload identity federation, so there are no Azure secrets anywhere. Three app registrations, each with only what it needs:

| Service connection | App | What it can do |
|---|---|---|
| `detections-read` | `<repo>-read` | Run advanced hunting queries (`ThreatHunting.Read.All`) |
| `detections-detonate` | `<repo>-detonate` | Start, stop and run commands on the lab VM only (Virtual Machine Contributor on that VM) |
| `detections-deploy` | `<repo>-deploy` | Create and update custom detections (`CustomDetection.ReadWrite.All`) |

The read and deploy apps also get Reader on the lab's resource group. The pipeline's Azure CLI step needs one role somewhere in the subscription to sign in, and Reader on that group is the smallest one that works.

The block creates each app, grants its permissions, creates its service connection in Azure DevOps, and adds the federated credential that service connection asks for. Graph application permissions are granted as app role assignments, the same thing the portal's **Grant admin consent** button does. It's safe to run again.

```bash
(
set -euo pipefail
source ~/detections-lab.env
az devops configure --defaults organization="$ADO_ORG_URL" project="$ADO_PROJECT"
TENANT_ID="$(az account show --query tenantId -o tsv)"
SUB_ID="$(az account show --query id -o tsv)"
SUB_NAME="$(az account show --query name -o tsv)"
PROJECT_ID="$(az devops project show --project "$ADO_PROJECT" --query id -o tsv)"
VM_ID="$(az vm show --resource-group "$RG_LAB" --name "$VM_NAME" --query id -o tsv)"
RG_LAB_ID="$(az group show --name "$RG_LAB" --query id -o tsv)"
GRAPH_APP=00000003-0000-0000-c000-000000000000
GRAPH_SP="$(az ad sp show --id "$GRAPH_APP" --query id -o tsv)"
WORK="$(mktemp -d)"

app() {  # display name: prints the app (client) ID, creating the app and its service principal once
  local id
  id="$(az ad app list --display-name "$1" --query "[0].appId" -o tsv)"
  [ -n "$id" ] || id="$(az ad app create --display-name "$1" --query appId -o tsv)"
  az ad sp show --id "$id" -o none 2>/dev/null || az ad sp create --id "$id" -o none
  echo "$id"
}
role() {  # app ID, Azure role, scope
  az role assignment create --assignee-object-id "$(az ad sp show --id "$1" --query id -o tsv)" \
    --assignee-principal-type ServicePrincipal --role "$2" --scope "$3" -o none
}
graph_role() {  # app ID, Microsoft Graph application permission
  local sp role_id
  sp="$(az ad sp show --id "$1" --query id -o tsv)"
  role_id="$(az ad sp show --id "$GRAPH_APP" --query "appRoles[?value=='$2'].id | [0]" -o tsv)"
  [ -n "$role_id" ] || { echo "Microsoft Graph has no application permission named $2"; return 1; }
  if [ -z "$(az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/$sp/appRoleAssignments" \
      --query "value[?appRoleId=='$role_id'].id | [0]" -o tsv)" ]; then
    az rest --method post --url "https://graph.microsoft.com/v1.0/servicePrincipals/$sp/appRoleAssignments" \
      --body "{\"principalId\":\"$sp\",\"resourceId\":\"$GRAPH_SP\",\"appRoleId\":\"$role_id\"}" -o none
  fi
}
connection() {  # service connection name, app ID: creates the connection and its federated credential once
  local name="$1" app_id="$2" id issuer subject
  id="$(az devops service-endpoint list --query "[?name=='$name'].id | [0]" -o tsv)"
  if [ -z "$id" ]; then
    python3 - "$name" "$app_id" "$TENANT_ID" "$SUB_ID" "$SUB_NAME" "$PROJECT_ID" "$ADO_PROJECT" > "$WORK/$name.json" <<'EOF'
import json, sys
name, app_id, tenant, sub_id, sub_name, project_id, project = sys.argv[1:8]
print(json.dumps({
    "name": name, "type": "AzureRM", "url": "https://management.azure.com/",
    "authorization": {"scheme": "WorkloadIdentityFederation",
                      "parameters": {"tenantid": tenant, "serviceprincipalid": app_id}},
    "data": {"environment": "AzureCloud", "scopeLevel": "Subscription", "subscriptionId": sub_id,
             "subscriptionName": sub_name, "creationMode": "Manual"},
    "isShared": False, "isReady": True,
    "serviceEndpointProjectReferences": [{"projectReference": {"id": project_id, "name": project}, "name": name}],
}))
EOF
    id="$(az devops service-endpoint create --service-endpoint-configuration "$WORK/$name.json" --query id -o tsv)"
  fi
  issuer="$(az devops service-endpoint show --id "$id" --query authorization.parameters.workloadIdentityFederationIssuer -o tsv)"
  subject="$(az devops service-endpoint show --id "$id" --query authorization.parameters.workloadIdentityFederationSubject -o tsv)"
  if [ -z "$(az ad app federated-credential list --id "$app_id" --query "[?subject=='$subject'].id | [0]" -o tsv)" ]; then
    printf '{"name":"%s","issuer":"%s","subject":"%s","audiences":["api://AzureADTokenExchange"]}' \
      "$name" "$issuer" "$subject" > "$WORK/$name-credential.json"
    az ad app federated-credential create --id "$app_id" --parameters "$WORK/$name-credential.json" -o none
  fi
  echo "$name: service connection $id, app $app_id"
}

READ_ID="$(app "$REPO_NAME-read")"
DETONATE_ID="$(app "$REPO_NAME-detonate")"
DEPLOY_ID="$(app "$REPO_NAME-deploy")"
graph_role "$READ_ID" ThreatHunting.Read.All
graph_role "$DEPLOY_ID" CustomDetection.ReadWrite.All
role "$READ_ID" "Reader" "$RG_LAB_ID"
role "$DETONATE_ID" "Virtual Machine Contributor" "$VM_ID"
role "$DEPLOY_ID" "Reader" "$RG_LAB_ID"
connection detections-read "$READ_ID"
connection detections-detonate "$DETONATE_ID"
connection detections-deploy "$DEPLOY_ID"
rm -rf "$WORK"
)
```

Now the variable group the pipelines read, and your API keys. This block asks for each key without showing it, checks it with one free call (it asks the provider whether the key can see the model the pipeline uses), and stores it as a secret variable. Secret variables are encrypted, masked in logs, and only reach the pipeline steps that ask for them by name. The Anthropic key is required the first time. Press Enter at any other prompt to skip that service, or on a later run, to keep the key already saved.

The Sentry DSN is the last prompt, and it shows as you paste it. It's stored as a plain variable, because Sentry says a DSN only lets someone send events to your project, never read them. Plain variables reach every pipeline step without extra setup.

```bash
(
set -euo pipefail
source ~/detections-lab.env
az devops configure --defaults organization="$ADO_ORG_URL" project="$ADO_PROJECT"
secret() {  # prompt: reads a value without showing it
  local value
  read -r -s -p "$1 (it won't show), then press Enter: " value
  echo >&2
  printf '%s' "$value"
}
works() {  # name, HTTP status: stops the block unless the status is 200
  [ "$2" = 200 ] || { echo "The $1 key check returned HTTP $2. Check the key and run this block again."; exit 1; }
  echo "$1 key works."
}
GROUP_ID="$(az pipelines variable-group list --group-name detections --query '[0].id' -o tsv)"
if [ -z "$GROUP_ID" ]; then
  GROUP_ID="$(az pipelines variable-group create --name detections --authorize false \
    --description "Names and keys for the custom detections pipelines" \
    --variables "COMPANY_NAME=$COMPANY_NAME" --query id -o tsv)"
fi
saved() {  # variable name: prints true if the group already has it
  az pipelines variable-group variable list --group-id "$GROUP_ID" --query "contains(keys(@), '$1')" -o tsv
}
ANTHROPIC_KEY="$(secret "Paste your Anthropic API key, or press Enter to keep the saved one")"
if [ -n "$ANTHROPIC_KEY" ]; then
  for MODEL in claude-opus-5-5 claude-fable-5-1 claude-haiku-5-5; do
    works "Anthropic ($MODEL)" "$(curl -s -o /dev/null -w '%{http_code}' -H "x-api-key: $ANTHROPIC_KEY" \
      -H 'anthropic-version: 2023-06-01' "https://api.anthropic.com/v1/models/$MODEL")"
  done
elif [ "$(saved ANTHROPIC_API_KEY)" != true ]; then
  echo "The Anthropic key is required."
  exit 1
fi
GEMINI_KEY="$(secret "Paste your Gemini API key, or press Enter to skip it or keep the saved one")"
[ -z "$GEMINI_KEY" ] || works Gemini "$(curl -s -o /dev/null -w '%{http_code}' -H "x-goog-api-key: $GEMINI_KEY" \
  https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash)"
OPENAI_KEY="$(secret "Paste your OpenAI API key, or press Enter to skip it or keep the saved one")"
[ -z "$OPENAI_KEY" ] || works OpenAI "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $OPENAI_KEY" \
  https://api.openai.com/v1/models/gpt-6.1-sol)"
NIMBLE_KEY="$(secret "Paste your Nimble API key, or press Enter to skip it or keep the saved one")"
[ -z "$NIMBLE_KEY" ] || works Nimble "$(curl -s -o /dev/null -w '%{http_code}' -X POST https://sdk.nimbleway.com/v2/search \
  -H "Authorization: Bearer $NIMBLE_KEY" -H 'Content-Type: application/json' \
  -d '{"query":"DFIR report","max_results":1,"search_depth":"lite"}')"
read -r -p "Paste your Sentry DSN, or press Enter to skip it or keep the saved one: " SENTRY_VALUE
DSN_SHAPE='^https://[0-9a-f]+(:[0-9a-f]+)?@[A-Za-z0-9.-]+(/[^/]+)*/[0-9]+$'
if [ -n "$SENTRY_VALUE" ] && ! [[ "$SENTRY_VALUE" =~ $DSN_SHAPE ]]; then
  echo "That doesn't look like a Sentry DSN (https://<key>@<host>/<project number>). Run this block again."
  exit 1
fi
setvar() {  # name, value, secret (true or false)
  local action=create
  [ "$(saved "$1")" != true ] || action=update
  if [ "$3" != true ]; then
    az pipelines variable-group variable "$action" --group-id "$GROUP_ID" --name "$1" --value "$2" -o none
  elif [ "$action" = create ]; then
    env "AZURE_DEVOPS_EXT_PIPELINE_VAR_$1=$2" az pipelines variable-group variable create \
      --group-id "$GROUP_ID" --name "$1" --secret true -o none
  else  # update reads the environment variable only with --prompt-value true
    env "AZURE_DEVOPS_EXT_PIPELINE_VAR_$1=$2" az pipelines variable-group variable update \
      --group-id "$GROUP_ID" --name "$1" --secret true --prompt-value true -o none
  fi
}
setvar COMPANY_NAME "$COMPANY_NAME" false
setvar LAB_RESOURCE_GROUP "$RG_LAB" false
setvar LAB_VM "$VM_NAME" false
[ -z "$ANTHROPIC_KEY" ] || setvar ANTHROPIC_API_KEY "$ANTHROPIC_KEY" true
[ -z "$GEMINI_KEY" ] || setvar GEMINI_API_KEY "$GEMINI_KEY" true
[ -z "$OPENAI_KEY" ] || setvar OPENAI_API_KEY "$OPENAI_KEY" true
[ -z "$NIMBLE_KEY" ] || setvar NIMBLE_API_KEY "$NIMBLE_KEY" true
[ -z "$SENTRY_VALUE" ] || setvar SENTRY_DSN "$SENTRY_VALUE" false
unset ANTHROPIC_KEY GEMINI_KEY OPENAI_KEY NIMBLE_KEY
az pipelines variable-group variable list --group-id "$GROUP_ID" -o table
)
```

The table shows secret values as blank or masked. That's expected. To change a key later, run this block again, paste the new key, and press Enter at the others to keep them.

## Step 6. Put the code in your repo

Upload `custom-detections.bundle` with Cloud Shell's **Manage files > Upload**. It lands in your home folder. A bundle is the whole Git repo in one file, history included, so the commit times show when each part was written. This clones it and points it at your Azure DevOps repo.

```bash
(
set -euo pipefail
source ~/detections-lab.env
az devops configure --defaults organization="$ADO_ORG_URL" project="$ADO_PROJECT"
[ -f ~/custom-detections.bundle ] || { echo "Upload custom-detections.bundle first (Manage files > Upload)."; exit 1; }
[ ! -e "$REPO_DIR" ] || { echo "$REPO_DIR already exists. Rename it, then run this again."; exit 1; }
git clone --quiet --branch main ~/custom-detections.bundle "$REPO_DIR"
cd "$REPO_DIR"
git remote set-url origin "$(az repos show --repository "$REPO_NAME" --query remoteUrl -o tsv)"
git config user.name "$(gh api user --jq '.name // .login')"
git config user.email "$(gh api user --jq '"\(.id)+\(.login)@users.noreply.github.com"')"
git log --format='%h %ad %s' --date=format:'%Y-%m-%d %H:%M %z'
)
```

The last two `git config` lines keep your personal email out of the history, because Step 14 publishes it.

## Step 7. Dry run in Cloud Shell

This sets up Python, runs the unit tests and the static checks, and shows exactly what would be sent to Defender, without sending anything.

```bash
(
set -euo pipefail
source ~/detections-lab.env
cd "$REPO_DIR"
python3 -m venv ~/.venvs/detections
~/.venvs/detections/bin/pip install --quiet --disable-pip-version-check -r requirements.txt
~/.venvs/detections/bin/python -m unittest discover --buffer --start-directory tests --top-level-directory .
~/.venvs/detections/bin/python -m scripts.rules detections
~/.venvs/detections/bin/python -m scripts.deploy detections/lab/defender-exclusion-added-from-command-line.yaml --dry-run | head -8
)
```

What good looks like: `OK` after the tests, `PASS` for the rule, and a `DRY RUN` line with the name `<your COMPANY_NAME> - MDE - Defender exclusion added from the command line` and `status=disabled`.

## Step 8. First push, pipelines and permissions

This pushes the code to `main`, creates the five pipelines, lets each one use only the service connections it needs, and lets the project's build service push `ai/` and `promote/` branches and open pull requests. Branch policies (next step) still apply to everything the build service does.

```bash
(
set -euo pipefail
source ~/detections-lab.env
az devops configure --defaults organization="$ADO_ORG_URL" project="$ADO_PROJECT"
cd "$REPO_DIR"
TOKEN="$(az account get-access-token --resource "$ADO_RESOURCE" --query accessToken -o tsv)"
git -c http.extraheader="AUTHORIZATION: bearer $TOKEN" push --quiet origin main
PROJECT_ID="$(az devops project show --project "$ADO_PROJECT" --query id -o tsv)"
REPO_ID="$(az repos show --repository "$REPO_NAME" --query id -o tsv)"
PROJECT_URL="$ADO_ORG_URL/$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$ADO_PROJECT")"
pipeline() {  # name, YAML path: prints the pipeline ID, creating it once
  local id
  id="$(az pipelines list --name "$1" --query '[0].id' -o tsv)"
  [ -n "$id" ] || id="$(az pipelines create --name "$1" --repository "$REPO_NAME" --repository-type tfsgit \
    --branch main --yaml-path "$2" --skip-first-run true --query id -o tsv)"
  echo "$id"
}
permit() {  # resource type, resource ID, pipeline IDs: only these pipelines may use the resource
  local kind="$1" id="$2" body
  shift 2
  body="$(python3 -c 'import json, sys; print(json.dumps({"pipelines": [{"id": int(p), "authorized": True} for p in sys.argv[1:]]}))' "$@")"
  az rest --method patch --resource "$ADO_RESOURCE" \
    --url "$PROJECT_URL/_apis/pipelines/pipelinePermissions/$kind/$id?api-version=7.1-preview.1" --body "$body" -o none
}
endpoint() { az devops service-endpoint list --query "[?name=='$1'].id | [0]" -o tsv; }
CHECKS="$(pipeline "Rule checks" pipelines/pr-checks.yml)"
DRAFT="$(pipeline "Draft rules" pipelines/draft.yml)"
DETONATE="$(pipeline "Lab detonation" pipelines/detonate.yml)"
DEPLOY="$(pipeline "Deploy rules" pipelines/deploy.yml)"
SHADOW="$(pipeline "Shadow run" pipelines/shadow.yml)"
GROUP_ID="$(az pipelines variable-group list --group-name detections --query '[0].id' -o tsv)"
permit variablegroup "$GROUP_ID" "$CHECKS" "$DRAFT" "$DETONATE" "$DEPLOY" "$SHADOW"
permit endpoint "$(endpoint detections-read)" "$CHECKS" "$DRAFT" "$DETONATE" "$SHADOW"
permit endpoint "$(endpoint detections-detonate)" "$DETONATE"
permit endpoint "$(endpoint detections-deploy)" "$DEPLOY"
NAME="$ADO_PROJECT Build Service ($ADO_ORG)"
FILTER="$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$NAME")"
DESCRIPTOR="$(az rest --method get --resource "$ADO_RESOURCE" \
  --url "https://vssps.dev.azure.com/$ADO_ORG/_apis/identities?searchFilter=General&filterValue=$FILTER&api-version=7.1" \
  --query 'value[0].descriptor' -o tsv)"
if [ -n "$DESCRIPTOR" ]; then
  az rest --method post --resource "$ADO_RESOURCE" \
    --url "$ADO_ORG_URL/_apis/accesscontrolentries/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87?api-version=7.1" \
    --body "{\"token\":\"repoV2/$PROJECT_ID/$REPO_ID\",\"merge\":true,\"accessControlEntries\":[{\"descriptor\":\"$DESCRIPTOR\",\"allow\":16404,\"deny\":0}]}" -o none
  echo "$NAME can contribute, create branches and open pull requests."
else
  echo "Couldn't find $NAME. Set it by hand: Project settings > Repositories > $REPO_NAME > Security > $NAME: set Contribute, Create branch and Contribute to pull requests to Allow."
fi
az pipelines list --query "[].{pipeline:name, id:id}" -o table
)
```

`16404` is Contribute (4) + Create branch (16) + Contribute to pull requests (16384), on this one repo. The build service gets nothing that bypasses policies.

## Step 9. Lock main, add the checks, first deploy

This does three things:

1. **Protects `main`.** Every change needs a pull request with one approval (yours counts on your own pull requests), squash merges only, and the **Rule checks** pipeline passing. **Lab detonation** is an optional check you queue by hand.
2. **Adds checks to the service connections.** `detections-detonate` gets an approval check (you approve every detonation, like CCCS) and an exclusive lock (one detonation at a time). `detections-deploy` gets a branch control check, so only a protected `main` can deploy. The checks sit on the service connections, so a pull request that edits a pipeline file can't skip them.
3. **Deploys every rule** for the first time and waits for the result.

```bash
(
set -euo pipefail
source ~/detections-lab.env
az devops configure --defaults organization="$ADO_ORG_URL" project="$ADO_PROJECT"
REPO_ID="$(az repos show --repository "$REPO_NAME" --query id -o tsv)"
CHECKS="$(az pipelines list --name "Rule checks" --query '[0].id' -o tsv)"
DETONATE="$(az pipelines list --name "Lab detonation" --query '[0].id' -o tsv)"
DEPLOY="$(az pipelines list --name "Deploy rules" --query '[0].id' -o tsv)"
PROJECT_URL="$ADO_ORG_URL/$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$ADO_PROJECT")"
policies() { az repos policy list --repository-id "$REPO_ID" --branch main --query "length([?type.displayName=='$1'])" -o tsv; }
if [ "$(policies 'Minimum number of reviewers')" = 0 ]; then
  az repos policy approver-count create --repository-id "$REPO_ID" --branch main --blocking true --enabled true \
    --minimum-approver-count 1 --creator-vote-counts true --allow-downvotes false --reset-on-source-push true -o none
fi
if [ "$(policies 'Require a merge strategy')" = 0 ]; then
  az repos policy merge-strategy create --repository-id "$REPO_ID" --branch main --blocking true --enabled true \
    --allow-squash true --allow-no-fast-forward false --allow-rebase false --allow-rebase-merge false -o none
fi
if [ "$(policies 'Build')" = 0 ]; then
  az repos policy build create --repository-id "$REPO_ID" --branch main --blocking true --enabled true \
    --build-definition-id "$CHECKS" --display-name "Rule checks" --manual-queue-only false \
    --queue-on-source-update-only true --valid-duration 0 -o none
  az repos policy build create --repository-id "$REPO_ID" --branch main --blocking false --enabled true \
    --build-definition-id "$DETONATE" --display-name "Lab detonation" --manual-queue-only true \
    --queue-on-source-update-only true --valid-duration 0 -o none
fi
ME="$(az devops user show --user "$(az ad signed-in-user show --query userPrincipalName -o tsv)" --query id -o tsv)"
WORK="$(mktemp -d)"
add_check() {  # service connection name, kind (approval, lock or branch)
  local id existing
  id="$(az devops service-endpoint list --query "[?name=='$1'].id | [0]" -o tsv)"
  existing="$(az rest --method get --resource "$ADO_RESOURCE" \
    --url "$PROJECT_URL/_apis/pipelines/checks/configurations?resourceType=endpoint&resourceId=$id&\$expand=settings&api-version=7.1-preview.1" \
    --query "value[].type.name" -o tsv)"
  case "$2:$existing" in
    approval:*Approval*|lock:*ExclusiveLock*|branch:*"Task Check"*) echo "$1 already has its $2 check."; return 0 ;;
  esac
  python3 - "$id" "$1" "$2" "$ME" > "$WORK/check.json" <<'EOF'
import json, sys
endpoint, name, kind, me = sys.argv[1:5]
body = {"resource": {"type": "endpoint", "id": endpoint, "name": name}, "timeout": 1440}
if kind == "approval":
    body["type"] = {"id": "8c6f20a7-a545-4486-9777-f762fafe0d4d", "name": "Approval"}
    body["settings"] = {"approvers": [{"id": me}], "minRequiredApprovers": 0, "requesterCannotBeApprover": False,
                        "instructions": "Read the fire plan comment on the pull request first. Approve only if the "
                                        "pull request changes nothing but rule and Sigma files."}
elif kind == "lock":
    body["type"] = {"id": "2ef31ad6-baa0-403a-8b45-2cbc9b4e5563", "name": "ExclusiveLock"}
    body["settings"] = {}
else:
    body["type"] = {"id": "fe1de3ee-a436-41b4-bb20-f6eb4cb879a7", "name": "Task Check"}
    body["settings"] = {"displayName": "Branch control",
                        "definitionRef": {"id": "86b05a0c-73e6-4f7d-b3cf-e38f3b39a75b",
                                          "name": "evaluatebranchProtection", "version": "0.0.1"},
                        "inputs": {"allowedBranches": "refs/heads/main", "ensureProtectionOfBranch": "true",
                                   "allowUnknownStatusBranch": "false"},
                        "retryInterval": 5}
print(json.dumps(body))
EOF
  az rest --method post --resource "$ADO_RESOURCE" \
    --url "$PROJECT_URL/_apis/pipelines/checks/configurations?api-version=7.1-preview.1" --body "@$WORK/check.json" -o none
  echo "$1: added the $2 check."
}
add_check detections-detonate approval
add_check detections-detonate lock
add_check detections-deploy branch
rm -rf "$WORK"
RUN_ID="$(az pipelines run --id "$DEPLOY" --branch main --parameters deployAll=true --query id -o tsv)"
echo "Deploy rules is running ($RUN_ID). Waiting for it to finish..."
while [ "$(az pipelines runs show --id "$RUN_ID" --query status -o tsv)" != completed ]; do sleep 20; done
echo "Deploy rules: $(az pipelines runs show --id "$RUN_ID" --query result -o tsv)"
)
```

When it says `succeeded`, the rule shows up in the Defender portal under **Hunting > Custom detection rules** as `<your COMPANY_NAME> - MDE - Defender exclusion added from the command line`, turned off.

If the deploy fails, open the run (**Pipelines > Deploy rules**). The log shows Defender's own error message. Two likely causes:

- **A tactic Defender doesn't accept.** Microsoft's docs only show tactic values by example (`Execution`). Create any custom detection by hand in the portal with the tactic you need, run `GET https://graph.microsoft.com/beta/security/rules/detectionRules` in Graph Explorer, copy the exact `tactic` string into `tactics` in `config/settings.yaml` and into the rule, delete the hand-made rule, and redeploy through a pull request.
- **403 Forbidden.** The Graph permission from Step 5 can take a few minutes to apply. Run the pipeline again with **Redeploy every rule** ticked.

## Step 10. Run one pull request through every gate

This bumps your own rule's version, so every gate runs once with a rule you trust.

```bash
(
set -euo pipefail
source ~/detections-lab.env
az devops configure --defaults organization="$ADO_ORG_URL" project="$ADO_PROJECT"
cd "$REPO_DIR"
TOKEN="$(az account get-access-token --resource "$ADO_RESOURCE" --query accessToken -o tsv)"
git switch --quiet main
git -c http.extraheader="AUTHORIZATION: bearer $TOKEN" pull --quiet --ff-only origin main
git switch --quiet -c test/first-pull-request
sed -i 's/^version: 1\.0\.0$/version: 1.0.1/' detections/lab/defender-exclusion-added-from-command-line.yaml
git commit --quiet -am "Bump the first rule's version to test every gate"
git -c http.extraheader="AUTHORIZATION: bearer $TOKEN" push --quiet -u origin test/first-pull-request
PR="$(az repos pr create --repository "$REPO_NAME" --source-branch test/first-pull-request --target-branch main \
  --title "Test the pull request flow" \
  --description "Version bump only. Runs Rule checks, the model reviews, Lab detonation and the deploy." \
  --query pullRequestId -o tsv)"
echo "Pull request $PR: $ADO_ORG_URL/$ADO_PROJECT/_git/$REPO_NAME/pullrequest/$PR"
)
```

Open the link. **Rule checks** starts by itself. In a few minutes it posts one comment:

- **Guard rails**: which files changed and whether that's allowed.
- **Static and Sigma checks**, then **Compiles**: advanced hunting compiled the query and returned its columns.
- **Production**: the rule over the last 3 days of your data, lab VM left out, with zero hits as the bar, like CCCS. Only the count is shown.
- **Red-side review**: Claude Fable's variants by tier, and whether this rule catches each.
- **Model jury**: Gemini's and GPT's verdicts, with what each found.

Then start the detonation: in the pull request, open **Checks**, find **Lab detonation**, and select **Queue**. Within a few minutes the bot posts a **fire plan**: the target VM as Defender sees it, the four exclusion tests with their tier (three baseline, one structural), the exact command and cleanup each one runs, the pinned Atomic Red Team commit, and the pre-flight checks. Read it. A detonation runs the branch's own pipeline and scripts, so only approve pull requests whose **Files** tab touches nothing outside `detections/` and `sigma/`.

Then open **Pipelines > Lab detonation**, select the waiting run, **Review**, and **Approve**. The run checks that the plan didn't change since it was posted, starts the VM, and runs a staging check (the machine that answers is the lab VM and its Defender sensor service is running). Then it runs the four tests 150 seconds apart and deallocates the VM. A second job waits 10 minutes for telemetry like CCCS did, keeps checking for up to 30 more minutes, and posts the results: each test's tier, whether the rule caught it, and the event counts the VM sent in that window, so a miss and missing telemetry look different. Defender may raise its own alert about the exclusions; in a lab, that's a good sign the sensor works.

Then approve the pull request and complete it (squash). That's your "approve" for the rule.

## Step 11. Turn on the AI drafter

It already runs every weekday at 11:17 UTC. Run it once now:

```bash
(source ~/detections-lab.env && az devops configure --defaults organization="$ADO_ORG_URL" project="$ADO_PROJECT" && az pipelines run --name "Draft rules" --branch main --query "{run:id, status:status}" -o table && echo "Watch it under Pipelines > Draft rules.")
```

What each run does:

1. **Research.** Nimble searches the live web for new reports on the trusted domains in `config/research.yaml`, and returns each page's text. The feeds in `config/feeds.yaml` and your write-ups in `inputs/` are added too.
2. **Triage.** Gemini screens each article: does it describe endpoint behavior the allowed tables record? (Claude Haiku if Gemini isn't set up.)
3. **Purple loop.** Claude Opus drafts the rule, a hunt query and a Sigma version, quoting the article for every point. Code checks the quotes and compiles the query in advanced hunting. Claude Fable lists bypasses by tier and Opus hardens the rule, up to 3 rounds.
4. **Model jury.** Gemini and GPT review the finished rule on their own. If either asks for changes, Opus revises once (it can reject findings that are wrong), the revision goes through the same checks, and they vote again.
5. **Pull request.** One per rule, labeled `ai-draft`, plus `jury-concerns` when the final vote wasn't unanimous.

The run's summary page (in the pipeline run, **Extensions** tab) lists every article and what happened to it, plus calls and tokens per model. With Sentry set up, the same run is a trace in Sentry: open **Explore > Agents** (or search **Traces** for the transaction `draft`) to see each article, the triage, blue, red and jury agents, every model call with its tokens and time, and the blue to red handoffs. Errors from any pipeline show up under **Issues**, tagged with the pipeline, build and pull request.

How to review each AI pull request:

1. **Files**: one rule under `detections/ai/`, its Sigma version under `sigma/ai/`, and nothing else. Rule checks fails the pull request otherwise.
2. **Rule checks comment.** A failed static or hunting check blocks completion. If the production check says `NOISY`, run the rule's query in **Advanced hunting** and look at every hit. If they're all true positives, add the label it names (`noise-reviewed-` plus the commit's first 7 characters) and queue Rule checks again. A new commit needs a new review.
3. **The source.** Each "Why this logic" point quotes the article, and code already checked the quote is really there. Check that the quote supports the point.
4. **The tier table and the jury.** NO in the tier table's last column is a gap the rule still has. A REVISE or REJECT vote says what another model family found. The models inform; you decide.
5. **Lab detonation**, if the rule lists lab tests: queue it, read the fire plan, approve. If it lists none, test it by hand, or add a matching Atomic test to `config/atomics.yaml` in its own pull request. Never let the AI add tests.
6. **Small fixes**: check out the branch, edit, push. Rule checks runs again.

To approve, approve and complete the pull request. To deny, run this. It asks for the pull request number and a one-line lesson, abandons the pull request, and opens a small pull request that adds the lesson to `feedback/lessons.md`. The blue side reads the last 40 lessons on every run.

```bash
(
set -euo pipefail
source ~/detections-lab.env
az devops configure --defaults organization="$ADO_ORG_URL" project="$ADO_PROJECT"
cd "$REPO_DIR"
read -r -p "Pull request number to deny: " PR
[[ "$PR" =~ ^[0-9]+$ ]] || { echo "Type the number only, like 42."; exit 1; }
read -r -p "Lesson (what was wrong, what to do instead): " LESSON
az repos pr update --id "$PR" --status abandoned -o none
TOKEN="$(az account get-access-token --resource "$ADO_RESOURCE" --query accessToken -o tsv)"
git switch --quiet main
git -c http.extraheader="AUTHORIZATION: bearer $TOKEN" pull --quiet --ff-only origin main
git switch --quiet -c "lesson/pr-$PR"
printf -- '- %s\n' "$LESSON" >> feedback/lessons.md
git commit --quiet -am "Lesson from denied AI draft $PR"
git -c http.extraheader="AUTHORIZATION: bearer $TOKEN" push --quiet -u origin "lesson/pr-$PR"
LESSON_PR="$(az repos pr create --repository "$REPO_NAME" --source-branch "lesson/pr-$PR" --target-branch main \
  --title "Lesson from denied AI draft $PR" --description "Adds one line to feedback/lessons.md." \
  --query pullRequestId -o tsv)"
git switch --quiet main
echo "Abandoned pull request $PR. Approve and complete the lesson: $ADO_ORG_URL/$ADO_PROJECT/_git/$REPO_NAME/pullrequest/$LESSON_PR"
)
```

Two more ways in:

- **One article now.** **Pipelines > Draft rules > Run pipeline**, and paste a URL in **Article URL**. Only that article is drafted, from any https site, so pick the source yourself. Nimble extracts it if the key is set.
- **An analyst write-up.** Add a Markdown file under `inputs/` in a pull request: what the attacker did, step by step, with process names and command lines. `inputs/README.md` has the rules. Remove hostnames, usernames and IP addresses first.

## Step 12. Shadow run, then promote

Rules in `testing` are deployed turned off, because custom detections have no "alerts but no incidents" mode. Once a day, **Shadow run** runs each one over the last 3 days with the lab VM left out and writes the count to the run's summary. Counts only. When a rule has spent 7 days in testing with zero hits, it opens a promotion pull request (CCCS's last step). Completing it turns the rule on; abandoning it says no, and that rule isn't proposed again. Run it now to see it work:

```bash
(source ~/detections-lab.env && az devops configure --defaults organization="$ADO_ORG_URL" project="$ADO_PROJECT" && az pipelines run --name "Shadow run" --branch main --query "{run:id, status:status}" -o table)
```

Before you complete a promotion, check what the shadow run can't: true-positive evidence (a passing Lab detonation or a documented manual test), and a name, description and entities a Tier 1 analyst can act on without asking you. To promote a rule by hand, or retire one, edit it with `python -m scripts.promote <rule file>` (add `--retire` to retire) on a branch, then open a pull request. Don't delete or rename rule files: Rule checks blocks both, because the old rule would keep running in Defender.

## Step 13. The CCCS skills in Claude Code

CCCS drove its loop with Claude Code skills. This repo has matching ones in `.claude/skills/`: `/purple-loop`, `/ensure-auth`, `/run-analytic`, `/export-analytic`, `/plan-variants`, `/detonate` and `/verify-evasion`. They run on your own computer and use the Azure CLI with the Azure DevOps extension. Every Defender query and every lab run still happens in the pipelines, so the approvals stay where they are.

On your Mac: install the Azure CLI (`brew install azure-cli`), run `az login` and `az extension add --name azure-devops`, clone your repo from Azure DevOps (`git clone https://dev.azure.com/<org>/<project>/_git/<repo>`), open Claude Code in that folder, and type `/ensure-auth`. Then `/purple-loop <pull request number>` walks one AI pull request through export, variant planning, detonation (you approve in Azure DevOps), verification by tier, your decision, hardening and the record. It asks before it changes or commits anything. `/plan-variants` only picks existing Atomic Red Team tests for you to allowlist; it never writes attack code.

## Step 14. Publish the open-source copy on GitHub

Azure DevOps can't host public projects anymore, so the public copy lives on GitHub. This pushes `main`, history included, to a new public repo. Nothing in the repo is secret: keys live in the variable group, and the identities are federated.

```bash
(
set -euo pipefail
source ~/detections-lab.env
cd "$REPO_DIR"
TOKEN="$(az account get-access-token --resource "$ADO_RESOURCE" --query accessToken -o tsv)"
git switch --quiet main
git -c http.extraheader="AUTHORIZATION: bearer $TOKEN" pull --quiet --ff-only origin main
gh auth setup-git
if gh repo view "$GH_REPO" >/dev/null 2>&1; then
  git push --quiet "https://github.com/$GH_REPO.git" main
else
  gh repo create "$GH_REPO" --public --source . --remote github --push \
    --description "Defender XDR custom detections as code: Nimble research, a Claude purple loop, a Gemini and OpenAI jury, approvals in Azure DevOps"
fi
echo "Public copy: https://github.com/$GH_REPO"
)
```

Run it again whenever you want the public copy to catch up.

## Step 15. Keep it healthy

- Once a month, start the VM for an hour so Windows and Defender update, then deallocate it. Start it with the first line, wait an hour, then run the second:

```bash
(source ~/detections-lab.env && az vm start --resource-group "$RG_LAB" --name "$VM_NAME" && echo "$VM_NAME is running. Deallocate it in an hour.")
```

```bash
(source ~/detections-lab.env && az vm deallocate --resource-group "$RG_LAB" --name "$VM_NAME" --no-wait && echo "Deallocating $VM_NAME")
```

- Rotate the API keys every few months: make new keys, run the second block of Step 5 again, then revoke the old ones in each console.
- Free tier minutes: every job here stays under 60 minutes, and a normal day (one Draft rules run, one Shadow run, a few pull requests) uses well under the 1,800 a month.
- If the Defender sensor on the VM shows **Inactive** after a long break, start the VM for an hour before the next detonation.

## The security model, in one table

| Input or actor | What could go wrong | What stops it |
|---|---|---|
| Threat articles (Nimble, feeds, URLs) | Prompt injection, hidden instructions, poisoned logic | Trusted domains only (Nimble filters, code checks every URL again); code does all fetching; hidden page content dropped (Nimble's main-content extraction, or code when Nimble is off); article tags neutralized; every answer locked to a JSON schema; no model has tools; optional Prompt Shields; human review |
| Model output | KQL that reaches outside data, huge scans, exclusions copied from the article, response actions, made-up reasoning | Blocked KQL, table allowlist, response actions rejected, compile and production checks, evidence quotes checked word for word, three model families reviewing, reviewer checklist |
| Red side or a juror declines or fails | Silent gap in review | Red side falls back to Opus; every vote, including "not set up" and "no answer", is shown on the pull request |
| A juror is wrong | Bad change pushed into the rule | Opus may reject findings that are wrong; the revision goes through the same static, compile and production checks; you see both votes |
| API keys (Anthropic, Gemini, OpenAI, Nimble) | Leaked key, runaway spend | Secret variables, encrypted and masked in logs, mapped only into the two pipeline steps that call models; never in the repo; each checked before it's stored; spend limits in each console; rotate in Step 15 |
| What the models see | Tenant data sent to a third party | Models get public article text and rule KQL only. Hunting results never reach a model; checks only ask for column names or counts |
| Sentry | Prompts, articles, answers, hunting data or keys sent to another third party | Only metadata leaves: errors without local variables, step timings, HTTP calls by URL, model names, roles and token counts. Sentry's own AI integrations, which can record prompts, are off; no trace headers are added to outgoing calls; every event is scrubbed of the key values before it's sent. The tests check each of these against the real SDK |
| Pull request comments and logs | Hunting rows leaked | Checks only ask for column names or counts; lab telemetry is counted by table, never shown as rows |
| Graph permissions | Tenant-wide read of hunting data; tenant-wide write of custom detections | Workload identity federation, no Azure secrets; read and deploy apps split; deploy only from a protected `main` (branch control check); each service connection authorized for named pipelines only |
| Bot pull requests | AI-written changes merged unseen | Build service can push branches and open pull requests, nothing more; one approval and Rule checks required; `ai/` branches may only add files under `detections/ai/` and `sigma/ai/` |
| Lab detonation | Arbitrary code on the VM | No AI-written attack code; allowlisted tests pinned to one commit with a SHA-256; every command shown in the fire plan before you approve; plan hash checked again before the VM starts; approval check and exclusive lock on the service connection; staging check; no inbound network; deallocated after every run; nightly auto-shutdown |
| Deployment | A bad rule paging people | Pull request, approval and checks required; static checks again at deploy; new rules deploy turned off |
| Supply chain | A compromised dependency | Exact package pins; Atomic file hash-pinned |

What's left over, said plainly: Python's transitive dependencies aren't hash-locked (`pip-compile --generate-hashes` would close that). A prompt-injected article can still nudge a rule toward being weak, and only your review catches that. Anyone with write access to the repo can change pipeline files on a branch and use the read app's hunting access and the API keys from a pull request build, so only give write access to people you'd trust with that. On Gemini's free tier, Google may use prompts to improve its products; the pipeline sends public article text and rule KQL, never your tenant's data.

## Things to confirm in your tenant

- The exact `tactic` strings Defender accepts (Step 9 shows how to check).
- Whether `getschema` works in your advanced hunting. If not, the compile check falls back to running the query with `take 0` and reading the column list, and says so if no columns come back.
- Whether Claude Fable 5.1 answers the red-side prompt. It has extra cybersecurity safeguards and may decline some prompts; declines fall back to Opus 4.8, and the pull request says which model answered. On the first live run, Fable declined and Opus 4.8 answered.
- API rate limits on new accounts. A `429` that outlasts the retries shows as "no answer" on that model's row; the run carries on.
- Your Nimble trial budget. When it runs out, Nimble returns `402`, the run summary says so, and the feeds still work.
- Your Sentry trial. If Sentry stops taking events, the pipeline runs the same; only the traces stop. A DSN that isn't valid turns Sentry off for that run with a warning.
- If an Azure sign-in in a pipeline fails with `AADSTS700213` or `AADSTS70021`, the federated credential from Step 5 doesn't match the service connection. Run the first block of Step 5 again.
- Defender portal menus move often. If a click path here doesn't match, search the portal for the page name.

## Sources

- [CCCS: How the Canadian Centre for Cyber Security used frontier AI to accelerate detection engineering](https://www.cyber.gc.ca/en/guidance/canadian-centre-cyber-security-used-frontier-ai-accelerate-detection-engineering)
- [Microsoft Graph (beta): Create detectionRule](https://learn.microsoft.com/graph/api/security-rulesroot-post-detectionrules?view=graph-rest-beta)
- [Microsoft Graph (beta): alertTemplate](https://learn.microsoft.com/graph/api/resources/security-alerttemplate?view=graph-rest-beta), [ruleSchedule](https://learn.microsoft.com/graph/api/resources/security-ruleschedule?view=graph-rest-beta), [entityMappingConfiguration](https://learn.microsoft.com/graph/api/resources/security-entitymappingconfiguration?view=graph-rest-beta)
- [Microsoft Graph (v1.0): runHuntingQuery](https://learn.microsoft.com/graph/api/security-security-runhuntingquery?view=graph-rest-1.0)
- [Microsoft Learn: Enable Defender for Servers at the resource level](https://learn.microsoft.com/azure/defender-for-cloud/tutorial-enable-servers-plan#enable-defender-for-servers-at-the-resource-level)
- [Microsoft Learn: Use scripts to automate Azure Resource Manager with workload identity service connections](https://learn.microsoft.com/azure/devops/pipelines/release/automate-service-connections?view=azure-devops)
- [Microsoft Learn: Configure and pay for parallel jobs](https://learn.microsoft.com/azure/devops/pipelines/licensing/concurrent-jobs?view=azure-devops)
- [Microsoft Learn: AzureCLI@2 task](https://learn.microsoft.com/azure/devops/pipelines/tasks/reference/azure-cli-v2?view=azure-pipelines) and [its source, which sets the AZURESUBSCRIPTION_* variables](https://github.com/microsoft/azure-pipelines-tasks/blob/master/Tasks/AzureCLIV2/azureclitask.ts)
- [Azure Identity for Python: AzurePipelinesCredential](https://learn.microsoft.com/python/api/azure-identity/azure.identity.azurepipelinescredential?view=azure-python)
- [Azure DevOps REST: Pull Request Labels](https://learn.microsoft.com/rest/api/azure/devops/git/pull-request-labels/list?view=azure-devops-rest-7.1)
- [Anthropic API documentation](https://docs.claude.com/en/api/overview)
- [OpenAI API: models](https://developers.openai.com/api/docs/models)
- [Gemini API: models](https://ai.google.dev/gemini-api/docs/models) and [structured output](https://ai.google.dev/gemini-api/docs/structured-output)
- [Nimble API: Search](https://docs.nimbleway.com/api-reference/search/search.md) and [Extract](https://docs.nimbleway.com/api-reference/extract/extract.md)
- [Sentry: AI agent monitoring for Python](https://docs.sentry.io/platforms/python/tracing/instrumentation/custom-instrumentation/ai-agents-module/), [what a DSN allows](https://docs.sentry.io/concepts/key-terms/dsn-explainer/), and [the Python SDK source](https://github.com/getsentry/sentry-python), whose `gen_ai` span names and attributes `scripts/observability.py` follows
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) and [Invoke-AtomicRedTeam, whose executor launch the lab script follows](https://github.com/redcanaryco/invoke-atomicredteam)
- [Claude Code docs: Skills](https://code.claude.com/docs/en/skills)
