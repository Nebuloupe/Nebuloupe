from engine.auth import get_aws_session
from engine.auth import get_azure_credentials
from engine.core_loop import start_scan

def main():
    session = get_aws_session()
    if session:
        # Pass the "passport" (session) to the engine
        start_scan(session)
    else:
        print("Exiting...")
    # azure_credentials = get_azure_credentials()
    # if azure_credentials:
    #     # Pass the "passport" (session) to the engine
    #     start_scan(azure_credential=azure_credentials,cloud_scope="azure")
    # else:
    #     print("Exiting...")

if __name__ == "__main__":
    main()