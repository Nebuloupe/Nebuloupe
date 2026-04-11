import boto3
import logging
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

# Suppress verbose Azure CLI/Identity logging
logging.getLogger('azure.identity').setLevel(logging.ERROR)
logging.getLogger('azure.core').setLevel(logging.ERROR)
logging.getLogger('azure.mgmt').setLevel(logging.ERROR)

# GCP imports
try:
    import google.auth
    from google.auth.exceptions import DefaultCredentialsError
except ImportError:
    google = None
    DefaultCredentialsError = Exception

# Azure imports
try:
    from azure.identity import DefaultAzureCredential
    from azure.identity._exceptions import CredentialUnavailableError
    from azure.core.exceptions import ClientAuthenticationError
except ImportError:
    DefaultAzureCredential = None
    CredentialUnavailableError = Exception
    ClientAuthenticationError = Exception


class AuthError(Exception):
    """Raised when cloud authentication fails with user-actionable guidance."""


def _raise_auth_error(lines):
    message = "\n".join(lines)
    print(message)
    raise AuthError(message)


def get_aws_session(region="us-east-1"):
    """
    Authenticate with AWS using default credential resolution chain:
    Environment Variables first (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY),
    then fallback to local CLI config (~/.aws/credentials).
    """
    try:
        session = boto3.Session(region_name=region)
        identity = session.client("sts").get_caller_identity()
        print(f"[+] AWS authenticated (Account: {identity['Account']})")
        return session

    except (NoCredentialsError, PartialCredentialsError) as e:
        _raise_auth_error([
            "",
            "[!] AWS Authentication Failed",
            "    No valid AWS credentials could be found.",
            "",
            "    Please authenticate using one of the following methods:",
            "    1. CI/CD Environment: Set AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY",
            "    2. Local Development: Run 'aws configure'",
        ])
    except Exception as e:
        _raise_auth_error([
            "",
            f"[!] Unexpected AWS authentication error: {e}",
        ])


def get_azure_credentials():
    """
    Authenticate with Azure strictly using DefaultAzureCredential.
    Resolution chain:
    Environment Variables first (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID),
    then fallback to local CLI identity (az login).
    Browser login completely disabled.
    """
    if DefaultAzureCredential is None:
        _raise_auth_error([
            "[-] Azure identity library (azure-identity) not installed.",
        ])

    try:
        # Exclude browser, exclude GUI prompts to ensure headless execution
        credential = DefaultAzureCredential(
            exclude_interactive_browser_credential=True,
            exclude_shared_token_cache_credential=True
        )
        # Attempt to get a token to early trigger credential validation
        credential.get_token("https://management.azure.com/.default")
        print("[+] Azure authenticated via DefaultAzureCredential.")
        return credential

    except (CredentialUnavailableError, ClientAuthenticationError) as e:
        _raise_auth_error([
            "",
            "[!] Azure Authentication Failed",
            "    No valid Azure credentials could be found.",
            "",
            "    Please authenticate using one of the following methods:",
            "    1. CI/CD Environment: Set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, & AZURE_TENANT_ID",
            "    2. Local Development: Run 'az login'",
        ])
    except Exception as e:
        if "CredentialUnavailableError" in str(type(e)):
            _raise_auth_error([
                "",
                "[!] Azure Authentication Failed",
                "    No valid Azure credentials could be found.",
                "",
                "    Please authenticate using one of the following methods:",
                "    1. CI/CD Environment: Set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, & AZURE_TENANT_ID",
                "    2. Local Development: Run 'az login'",
            ])
            
        _raise_auth_error([
            "",
            f"[!] Unexpected Azure authentication error: {e}",
        ])


def get_gcp_project():
    """
    Authenticate with GCP securely using Application Default Credentials (ADC).
    Resolution chain:
    Environment variable first (GOOGLE_APPLICATION_CREDENTIALS),
    then fallback to gcloud default credentials.
    """
    if google is None:
        _raise_auth_error([
            "[-] Google auth library (google-auth) not installed.",
        ])

    try:
        credentials, project = google.auth.default()
        if project:
            print(f"[+] Found GCP Project via ADC: {project}")
        else:
            print("[-] Unable to determine GCP Project ID from ADC.")
            
        return project

    except DefaultCredentialsError as e:
        _raise_auth_error([
            "",
            "[!] GCP Authentication Failed",
            "    Could not locate Application Default Credentials (ADC).",
            "",
            "    Please authenticate using one of the following methods:",
            "    1. CI/CD Environment: Set GOOGLE_APPLICATION_CREDENTIALS to the JSON key path",
            "    2. Local Development: Run 'gcloud auth application-default login'",
        ])
    except Exception as e:
        _raise_auth_error([
            "",
            f"[!] Unexpected GCP authentication error: {e}",
        ])

if __name__ == "__main__":
    pass
