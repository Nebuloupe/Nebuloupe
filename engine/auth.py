import sys
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
        print("\n[!] AWS Authentication Failed")
        print("    No valid AWS credentials could be found.")
        print("\n    Please authenticate using one of the following methods:")
        print("    1. CI/CD Environment: Set AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY")
        print("    2. Local Development: Run 'aws configure'")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected AWS authentication error: {e}")
        sys.exit(1)


def get_azure_credentials():
    """
    Authenticate with Azure strictly using DefaultAzureCredential.
    Resolution chain:
    Environment Variables first (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID),
    then fallback to local CLI identity (az login).
    Browser login completely disabled.
    """
    if DefaultAzureCredential is None:
        print("[-] Azure identity library (azure-identity) not installed.")
        sys.exit(1)

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
        print("\n[!] Azure Authentication Failed")
        print("    No valid Azure credentials could be found.")
        print("\n    Please authenticate using one of the following methods:")
        print("    1. CI/CD Environment: Set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, & AZURE_TENANT_ID")
        print("    2. Local Development: Run 'az login'")
        sys.exit(1)
    except Exception as e:
        if "CredentialUnavailableError" in str(type(e)):
            print("\n[!] Azure Authentication Failed")
            print("    No valid Azure credentials could be found.")
            print("\n    Please authenticate using one of the following methods:")
            print("    1. CI/CD Environment: Set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, & AZURE_TENANT_ID")
            print("    2. Local Development: Run 'az login'")
            sys.exit(1)
            
        print(f"\n[!] Unexpected Azure authentication error: {e}")
        sys.exit(1)


def get_gcp_project():
    """
    Authenticate with GCP securely using Application Default Credentials (ADC).
    Resolution chain:
    Environment variable first (GOOGLE_APPLICATION_CREDENTIALS),
    then fallback to gcloud default credentials.
    """
    if google is None:
        print("[-] Google auth library (google-auth) not installed.")
        sys.exit(1)

    try:
        credentials, project = google.auth.default()
        if project:
            print(f"[+] Found GCP Project via ADC: {project}")
        else:
            print("[-] Unable to determine GCP Project ID from ADC.")
            
        return project

    except DefaultCredentialsError as e:
        print("\n[!] GCP Authentication Failed")
        print("    Could not locate Application Default Credentials (ADC).")
        print("\n    Please authenticate using one of the following methods:")
        print("    1. CI/CD Environment: Set GOOGLE_APPLICATION_CREDENTIALS to the JSON key path")
        print("    2. Local Development: Run 'gcloud auth application-default login'")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected GCP authentication error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    pass
