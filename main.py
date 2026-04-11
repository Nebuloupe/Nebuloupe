import argparse
import sys
import logging
from engine.scanner import run_scanner

def main():
    parser = argparse.ArgumentParser(
    description="Nebuloupe - Cloud Misconfiguration Security Scanner",
        epilog="""
Examples:
  python main.py --cloud aws                                    # API scan only (needs AWS creds)
  python main.py --cloud aws --mode iac --tf-path ./terraform/  # IaC scan only (no creds needed)
  python main.py --cloud aws --tf-path ./terraform/             # IaC scan first, then API scan
  python main.py --cloud aws --tf-path ./infra/ --fail-on critical,high  # Gate: block on critical/high
        """
    )
    
    parser.add_argument(
        '--cloud',
        choices=['aws', 'azure', 'gcp'],
        required=True,
        help='Specify the cloud provider to scan'
    )
    
    parser.add_argument(
        '--mode',
        choices=['api', 'iac', 'all'],
        default='all',
        help='Scan mode: "api" (live cloud scan), "iac" (Terraform static analysis), "all" (IaC first, then API). Default: all'
    )
    
    parser.add_argument(
        '--tf-path',
        type=str,
        default=None,
        help='Path to directory containing Terraform (.tf) files for IaC scanning'
    )
    
    parser.add_argument(
        '--fail-on',
        type=str,
        default=None,
        help='Comma-separated severity levels that should cause a non-zero exit code. '
             'Example: --fail-on critical,high'
    )
    
    parser.add_argument(
        '--verbose',
        choices=['ERROR', 'INFO', 'DEBUG'],
        default='INFO',
        help='Set logging verbosity level. Default: INFO'
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

    logging.basicConfig(level=level, format="%(message)s", force=True)
    logging.getLogger().setLevel(level)

    # Validate: IaC mode requires --tf-path
    if args.mode in ['iac', 'all'] and args.tf_path:
        pass  # Good - tf_path provided for IaC scan
    elif args.mode == 'iac' and not args.tf_path:
        logging.error("[-] --tf-path is required when using --mode iac")
        sys.exit(1)
    elif args.mode == 'all' and not args.tf_path:
        # If mode is 'all' but no tf_path, fall back to API-only
        logging.info("[*] No --tf-path provided, falling back to API-only scan.")
        args.mode = 'api'

    # Parse fail-on severities
    fail_on_severities = []
    if args.fail_on:
        fail_on_severities = [s.strip().capitalize() for s in args.fail_on.split(',')]
        valid_severities = ['Critical', 'High', 'Medium', 'Low']
        for sev in fail_on_severities:
            if sev not in valid_severities:
                logging.error(f"[-] Invalid severity in --fail-on: '{sev}'. Valid: {valid_severities}")
                sys.exit(1)

    logging.info(f"")
    logging.info(f"  ╔══════════════════════════════════════════════╗")
    logging.info(f"  ║     🔭 NEBULOUPE Cloud Misconfiguration Security Scanner")
    logging.info(f"  ╚══════════════════════════════════════════════╝")
    logging.info(f"")
    logging.info(f"  [*] Cloud Scope : {args.cloud.upper()}")
    logging.info(f"  [*] Scan Mode   : {args.mode.upper()}")
    if args.tf_path:
        logging.info(f"  [*] Terraform   : {args.tf_path}")
    if fail_on_severities:
        logging.info(f"  [*] Fail On     : {', '.join(fail_on_severities)}")
    logging.info(f"")

    try:
        results = run_scanner(
            cloud_scope=args.cloud,
            mode=args.mode,
            tf_path=args.tf_path,
            fail_on_severities=fail_on_severities
        )
        
        if results:
            logging.info(f"\n[+] Scan completed successfully!")
            logging.info(f"[*] Results saved to: output/results.json")
            
            # Check fail-on gate
            if fail_on_severities and results.get("findings"):
                blocking_findings = [
                    f for f in results["findings"]
                    if f.get("severity") in fail_on_severities and f.get("status") == "FAIL"
                ]
                if blocking_findings:
                    logging.error(f"\n[!] GATE FAILED: {len(blocking_findings)} finding(s) "
                                  f"matched --fail-on {', '.join(fail_on_severities)}")
                    for bf in blocking_findings[:5]:
                        logging.error(f"    • [{bf.get('severity')}] {bf.get('check')}: {bf.get('description', '')[:80]}")
                    if len(blocking_findings) > 5:
                        logging.error(f"    ... and {len(blocking_findings) - 5} more")
                    sys.exit(1)
        else:
            logging.error("[-] Scan failed or yielded no results.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logging.error("\n[-] Scan interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        logging.error(f"[-] A fatal error occurred during the scan: {e}")
        import traceback
        logging.debug(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()