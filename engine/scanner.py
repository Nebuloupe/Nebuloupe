from engine.auth import get_aws_session, get_azure_credentials
from engine.core_loop import start_scan
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")

def run_scanner(cloud_scope):
    """
    Function provider for starting a scan.
    """
    logging.info(f"[*] Starting Nebuloupe scan for scope: {cloud_scope}")
    
    aws_session = None
    azure_credential = None

    if cloud_scope == "aws":
        aws_session = get_aws_session()
        if not aws_session:
            logging.warning("Could not obtain AWS session.")
            
    if cloud_scope == "azure":
        azure_credential = get_azure_credentials()
        if not azure_credential:
            logging.warning("Could not obtain Azure credentials.")
    
    if aws_session or azure_credential:
        return start_scan(aws_session=aws_session, azure_credential=azure_credential, cloud_scope=cloud_scope)
    else:
        logging.error("[-] No valid credentials found for the requested cloud scope. Exiting scan.")
        return None