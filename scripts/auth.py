"""Azure sign-in without secrets.

In Azure Pipelines, each AzureCLI@2 step signs in with its service connection
through workload identity federation and sets AZURESUBSCRIPTION_CLIENT_ID,
AZURESUBSCRIPTION_TENANT_ID and AZURESUBSCRIPTION_SERVICE_CONNECTION_ID.
AzurePipelinesCredential uses those to ask Azure DevOps for a fresh federated
token whenever it needs one, so long steps don't run into expired tokens.

On your own computer it uses your Azure CLI sign-in.
"""

from __future__ import annotations

import os

from .common import Fail


def credential():
    from azure.identity import AzureCliCredential, AzurePipelinesCredential

    service_connection = os.environ.get("AZURESUBSCRIPTION_SERVICE_CONNECTION_ID", "")
    if os.environ.get("SYSTEM_OIDCREQUESTURI") and service_connection:
        token = os.environ.get("SYSTEM_ACCESSTOKEN", "")
        if not token or token.startswith("$("):
            raise Fail("Map SYSTEM_ACCESSTOKEN: $(System.AccessToken) in this step's env so it can sign in to Azure.")
        return AzurePipelinesCredential(
            tenant_id=os.environ["AZURESUBSCRIPTION_TENANT_ID"],
            client_id=os.environ["AZURESUBSCRIPTION_CLIENT_ID"],
            service_connection_id=service_connection,
            system_access_token=token,
        )
    return AzureCliCredential()
