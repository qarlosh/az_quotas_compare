import json
from azure.identity import (
    ClientSecretCredential,
    InteractiveBrowserCredential,
)
from azure.mgmt.quota import QuotaMgmtClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
import argparse

DESCRIPTION = """Retrieve and compare quota limits for 2 subscriptions.

If no authentication arguments are provided, it uses the interactive browser authentication. Yo need to provide the following argument:
- Tenant ID (or "directory" ID): Same value that EaaS gets from AZURE_TENANT_ID environment variable.

For more explicit authentication, provide the rest of the arguments to use Client Secret authentication. You must provide them for both subscriptions:
- Client ID: Same value that EaaS gets from ACI_CLIENT_ID environment variable.
- Client Secret: Same value that EaaS gets from ACI_SECRET environment variable.
"""

def main():
    config = parse_args()
    if cs := config['client_secret_auth']:
        credentials = (
            ClientSecretCredential(
                config["tenant_id_1"],
                cs["client_id_1"],
                cs["client_secret_1"],
            ),
            ClientSecretCredential(
                config["tenant_id_2"],
                cs["client_id_2"],
                cs["client_secret_2"],
            ),
        )
    else:
        credentials = (
            InteractiveBrowserCredential(tenant_id=config["tenant_id_1"]),
            InteractiveBrowserCredential(tenant_id=config["tenant_id_2"]),
        )

    providers = get_resource_providers_from_file()
    # providers = get_resource_providers(credentials[0], config['subscription_id_1'])

    locations = get_locations_from_file()
    # locations = get_locations(credentials[0], config['subscription_id_1'])

    quota_limits = {}
    get_subscription_quota_limits(
        credentials[0], config["subscription_id_1"], providers, locations, quota_limits,
    )
    get_subscription_quota_limits(
        credentials[1], config["subscription_id_2"], providers, locations, quota_limits,
    )
    compare_and_show_results(quota_limits, config["subscription_id_1"], config["subscription_id_2"])


def parse_args():
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--subscription-id-1", required=True, help="Subscription ID #1")
    parser.add_argument("--subscription-id-2", required=True, help="Subscription ID #2")
    parser.add_argument(
        "--tenant-id-1",
        required=True,
        help="Tenant ID for subscription #1",
    )
    parser.add_argument(
        "--tenant-id-2",
        required=True,
        help="Tenant ID for subscription #2",
    )
    parser.add_argument(
        "--client-id-1",
        help="Client ID for subscription #1 (for client secret authentication)",
    )
    parser.add_argument(
        "--client-id-2",
        help="Client ID for subscription #2 (for client secret authentication)",
    )
    parser.add_argument(
        "--client-secret-1",
        help="Client secret for subscription #1 (for client secret authentication)",
    )
    parser.add_argument(
        "--client-secret-2",
        help="Client secret for subscription #2 (for client secret authentication)",
    )
    args = parser.parse_args()
    client_secret_auth_args = {
        'client_id_1': args.client_id_1,
        'client_id_2': args.client_id_2,
        'client_secret_1': args.client_secret_1,
        'client_secret_2': args.client_secret_2,
    }
    if not all(client_secret_auth_args.values()) and any(client_secret_auth_args.values()):
        parser.error(
            "To use client secret authentication you must provide all the arguments."
        )
    if not any(client_secret_auth_args.values()):
        # do not use client secret authentication
        client_secret_auth_args = None
    return {
        'tenant_id_1': args.tenant_id_1,
        'tenant_id_2': args.tenant_id_2,
        "subscription_id_1": args.subscription_id_1,
        "subscription_id_2": args.subscription_id_2,
        "client_secret_auth": client_secret_auth_args,
    }


def get_locations(credential, subscription_id):
    print(f"Retrieving locations for {subscription_id}...", end=' ', flush=True)
    client = SubscriptionClient(credential)
    locations = client.subscriptions.list_locations(subscription_id)
    result = [loc.name for loc in locations]
    print(f"got {len(result)}.")
    return result


def get_locations_from_file():
    print(f"Getting locations from file...", end=' ', flush=True)
    with open("locations.txt", "r") as f:
        result = [l.strip() for l in f.readlines()]
    result = [l for l in result if l]
    print(f"got {len(result)}.")
    return result


def get_resource_providers(credential, subscription_id):
    print(f"Retrieving resource providers for {subscription_id}...", end=' ', flush=True)
    client = ResourceManagementClient(credential, subscription_id)
    providers = client.providers.list()
    result = [provider.namespace for provider in providers]
    print(f"got {len(result)}.")
    return result


def get_resource_providers_from_file():
    print(f"Getting resource providers from file...", end=' ', flush=True)
    with open("providers.txt", "r") as f:
        result = [l.strip() for l in f.readlines()]
    result = [l for l in result if l]
    print(f"got {len(result)}.")
    return result


def get_subscription_quota_limits(credential, subscription_id, providers, locations, quota_limits):
    print(f"**** START RETRIEVING ALL QUOTAS FOR SUBSCRIPTION {subscription_id} ****")
    subs_quota_limits = {}
    quota_limits[subscription_id] = subs_quota_limits
    for provider in providers:
        subs_quota_limits[provider] = {}
        for location in locations:
            subs_quota_limits[provider][location] = {}
            quotas = retrieve_quotas(credential, subscription_id, provider, location)
            for quota in quotas:
                subs_quota_limits[provider][location][quota.name] = quota.properties.limit.value


def retrieve_quotas(credential, subscription_id, provider, location):
    print(f"Retrieving quotas for {provider} in {location}...", end=' ', flush=True)
    try:
        client = QuotaMgmtClient(credential=credential, subscription_id=subscription_id)
        scope = f"/subscriptions/{subscription_id}/providers/{provider}/locations/{location}"
        quotas = list(client.quota.list(scope))
        print(f"got {len(quotas)}.")
        return quotas
    except HttpResponseError as e:
        if e.status_code == 400:
            print(f"NOT AVAILABLE.")
            return []
        if isinstance(e, ResourceNotFoundError): # 404
            print(f"INVALID RESOURCE TYPE.")
            return []
        if e.status_code >= 400:
            print(f"CLIENT ERROR ({e.status_code}, {e.reason}).")
            return []
        if e.status_code >= 500:
            print(f"SERVER ERROR ({e.status_code}, {e.reason}).")
            return []
    except:
        print("\n")
        raise


def compare_and_show_results(quota_limits, subscription_id_1, subscription_id_2):
    # store results in file JSON format
    with open(f"limits_{subscription_id_1}.json", "w") as f:
        f.write(json.dumps(quota_limits[subscription_id_1], indent=4))
    with open(f"limits_{subscription_id_2}.json", "w") as f:
        f.write(json.dumps(quota_limits[subscription_id_2], indent=4))
    diffs = compare_dicts(quota_limits[subscription_id_1] , quota_limits[subscription_id_2])
    print("\nDIFFERENCES FOUND:")
    for d in diffs:
        print(d)


def compare_dicts(d1, d2, path=""):
    diffs = []

    keys_d1 = set(d1.keys())
    keys_d2 = set(d2.keys())

    for key in keys_d1 - keys_d2:
        diffs.append(f"{path}/{key}  IS IN #1 BUT NOT IN #2")

    for key in keys_d2 - keys_d1:
        diffs.append(f"{path}/{key}  IS IN #2 BUT NOT IN #1")

    for key in keys_d1 & keys_d2:
        val1 = d1[key]
        val2 = d2[key]
        new_path = f"{path}/{key}"

        if isinstance(val1, dict) and isinstance(val2, dict):
            diffs.extend(compare_dicts(val1, val2, new_path))
        elif val1 != val2:
            diffs.append(f"{new_path:<90}{val1:>6} | {val2:>6}")

    return diffs


if __name__ == "__main__":
    main()
