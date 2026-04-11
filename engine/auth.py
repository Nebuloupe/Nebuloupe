import boto3
import logging
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

# Suppress verbose Azure CLI/Identity logging
logging.getLogger('azure.identity').setLevel(logging.ERROR)
logging.getLogger('azure.core').setLevel(logging.ERROR)
logging.getLogger('azure.mgmt').setLevel(logging.ERROR)

# GCP imports
try:
    import google.auth
except ImportError:
    google = None

# Azure imports
try:
    from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential

    from azure.core.exceptions import ClientAuthenticationError
except ImportError:
    ClientSecretCredential  = None
    DefaultAzureCredential  = None
    InteractiveBrowserCredential = None


def get_aws_session(access_key=None, secret_key=None, region="us-east-1"):
    """
    Authenticate with AWS using local credentials or provided keys.
    Never calls input() — safe for Streamlit.
    """
    try:
        if access_key and secret_key:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region,
            )
        else:
            session = boto3.Session()

        identity = session.client("sts").get_caller_identity()
        print(f"[+] AWS authenticated (Account: {identity['Account']})")
        return session

    except Exception as e:
        print(f"[-] AWS authentication failed: {e}")
        return None


def get_azure_credentials(tenant_id=None, client_id=None, client_secret=None, **kwargs):
    """
    Authenticate with Azure.

    Priority:
    1. Service Principal (tenant_id + client_id + client_secret) — most reliable
    2. InteractiveBrowserCredential (tenant_id only) — opens browser tab
    3. DefaultAzureCredential — requires az login or env vars

    Never calls input() — safe for Streamlit.
    """
    if ClientSecretCredential is None:
        print("[-] Azure libraries not installed.")
        return None

    # Option 1: Service Principal credentials provided
    if tenant_id and client_id and client_secret:
        try:
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
            credential.get_token("https://management.azure.com/.default")
            print("[+] Azure authenticated via Service Principal.")
            return credential
        except Exception as e:
            print(f"[-] Azure Service Principal auth failed: {e}")
            return None

    # Option 2: Interactive browser (tenant_id optional)
    if tenant_id and InteractiveBrowserCredential:
        try:
            credential = InteractiveBrowserCredential(tenant_id=tenant_id)
            credential.get_token("https://management.azure.com/.default")
            print("[+] Azure authenticated via interactive browser.")
            return credential
        except Exception as e:
            print(f"[-] Azure interactive auth failed: {e}")
            return None

    # Option 3: Default (az login / env vars) — with short timeout
    if DefaultAzureCredential:
        try:
            import concurrent.futures
            credential = DefaultAzureCredential(
                exclude_interactive_browser_credential=True,
                exclude_shared_token_cache_credential=True,
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                future = ex.submit(
                    credential.get_token, "https://management.azure.com/.default"
                )
                future.result(timeout=8)   # fail fast if no local creds
            print("[+] Azure authenticated via local credentials.")
            return credential
        except Exception as e:
            print(f"[-] Azure default auth failed: {e}")
            return None

def get_gcp_project():
    """
    Attempts to get the GCP Project ID.
    1. Checks Application Default Credentials (ADC).
    2. If not found, prompts the user.
    """
    # Check if google module is available globally
    if "google" not in globals() or google is None:
        print("[-] Google auth libraries not installed.")
        # Fallback to prompt if google library isn't there
        project = input("\n    Enter Google Cloud Project ID: ").strip()
        return project if project else None

    print("\n[*] Attempting to determine GCP Project ID...")
    try:
        credentials, project = google.auth.default()
        if project:
            print(f"[+] Found GCP Project via ADC: {project}")
            return project
    except Exception as e:
        print(f"[-] Could not find default project via ADC: {e}")

    print("[*] Please enter your project ID manually:")
    project = input("    GCP Project ID: ").strip()
    return project if project else None

if __name__ == "__main__":
    # Test the scripts independently
    # print("Testing AWS Auth...")
    # get_aws_session()

    print("\nTesting Azure Auth...")
    # get_azure_credentials()
