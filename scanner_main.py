from engine.auth import get_aws_session
from engine.auth import get_azure_credentials
from engine.core_loop import start_scan

def main():
    # session = get_aws_session()
    # if session:
    #     # Pass the "passport" (session) to the engine
    #     start_scan(session)
    # else:
    #     print("Exiting...")
    session = get_azure_credentials()
    if session:
        # Pass the "passport" (session) to the engine
        start_scan(session)
    else:
        print("Exiting...")

if __name__ == "__main__":
    main()