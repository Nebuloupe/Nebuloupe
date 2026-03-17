import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

# Azure imports
try:
    from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
    from azure.core.exceptions import ClientAuthenticationError
except ImportError:
    DefaultAzureCredential = None
    InteractiveBrowserCredential = None

def get_aws_session():
    """
    Attempts to authenticate with AWS. 
    1. Checks local ~/.aws/credentials or Environment Variables.
    2. If not found, prompts the user for manual input.
    """
    try:
        # Step 1: Try to initialize with existing local config
        session = boto3.Session()
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        
        print(f" Authenticated using local credentials (Account: {identity['Account']})")
        return session

    except (NoCredentialsError, PartialCredentialsError, ClientError):
        print("\n--- AWS Credentials Not Found Locally ---")
        print("Please enter your credentials manually:")
        
        access_key = input("AWS Access Key ID: ").strip()
        secret_key = input("AWS Secret Access Key: ").strip()
        region = input("Default Region (e.g., us-east-1): ").strip() or "us-east-1"

        try:
            # Step 2: Try to initialize with user-provided keys
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            # Verify the manual keys work
            sts = session.client('sts')
            sts.get_caller_identity()
            
            print(f" Manual Authentication Successful!")
            return session
            
        except Exception as e:
            print(f" Failed to authenticate: {e}")
            return None

def get_azure_credentials():
    """
    Attempts to authenticate with Azure.
    1. Checks local Azure CLI, Environment Variables, etc.
    2. If not found or fails, prompts user for an interactive web login.
    """
    if DefaultAzureCredential is None:
        print("[!] Azure libraries not installed. Please run: pip install -r requirements.txt")
        return None

    print("\n🔍 Attempting to authenticate with Azure...")
    try:
        # Step 1: Try local config (CLI, Env vars) first, skipping interactive browser
        credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        # Verify it works by requesting a basic management token
        credential.get_token("https://management.azure.com/.default")
        print(" ✅ Authenticated using local Azure credentials.")
        return credential
        
    except Exception:
        print("\n--- Local Azure Credentials Not Found ---")
        print("Starting interactive web login fallback...")
        
        try:
            # Step 2: Fallback to interactive browser login
            credential = InteractiveBrowserCredential()
            # Verify the manual login works
            credential.get_token("https://management.azure.com/.default")
            print(" ✅ Interactive Authentication Successful!")
            return credential
            
        except Exception as ex:
            print(f" ❌ Failed to authenticate with Azure: {ex}")
            return None

if __name__ == "__main__":
    # Test the scripts independently
    # print("Testing AWS Auth...")
    # get_aws_session()
    
    print("\nTesting Azure Auth...")
    get_azure_credentials()