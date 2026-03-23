import argparse
import sys
import logging
from engine.scanner import run_scanner

def main():
    parser = argparse.ArgumentParser(
        description="Nebuloupe - Multi-Cloud Misconfiguration Security Scanner"
    )
    
    parser.add_argument(
        '--cloud',
        choices=['aws', 'azure'],
        help='Specify the cloud provider to scan'
    )
    
    parser.add_argument(
        '--verbose',
        choices=['ERROR', 'INFO', 'DEBUG'],
        default='ERROR',
        help='Enable verbose output during the scan'
    )
    
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    # Setup basic logging level depending on verbosity
    if args.verbose == 'DEBUG':
        level = logging.DEBUG
    elif args.verbose == 'INFO':
        level = logging.INFO
    else: 
        level = logging.ERROR

    logging.getLogger().setLevel(level)

    logging.info(f"[*] Starting Nebuloupe CLI...")
    logging.info(f"[*] Target Cloud Scope: {args.cloud.upper()}")

    try:
        results = run_scanner(cloud_scope=args.cloud)
        if results:
            logging.info(f"\n[+] Scan completed successfully!")
            logging.info(f"[*] Results saved to: output/results.json")
        else:
            logging.error("[-] Scan failed or yielded no results due to credential issues.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logging.error("\n[-] Scan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        logging.error(f"[-] A fatal error occurred during the scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()