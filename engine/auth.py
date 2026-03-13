import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

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

if __name__ == "__main__":
    # Test the script independently
    get_aws_session()