import importlib
import os
import json
from datetime import datetime
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
def start_scan(session):
    print("🔍 Scanning AWS Infrastructure...")
    
    # This is the final report structure
    full_report = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "cloud": "AWS",
            "account_id": session.client('sts').get_caller_identity()['Account']
        },
        "results": []
    }

    # Path to your AWS rules
    rules_path = os.path.join('rules', 'aws')
    
    # 1. Look for all .py files in rules/aws/ (excluding __init__.py)
    rule_files = [f[:-3] for f in os.listdir(rules_path) if f.endswith('.py') and f != '__init__.py']

    for rule_name in rule_files:
        try:
            # 2. Dynamically import the rule module
            # This is like doing: from rules.aws import s3_public
            module = importlib.import_module(f"rules.aws.{rule_name}")
            
            print(f"   [+] Running check: {rule_name}...")
            
            # 3. Execute the standard run_check function
            findings = module.run_check(session)
            
            full_report["results"].append({
                "rule": rule_name,
                "findings": findings
            })
        except Exception as e:
            print(f"   [!] Error running {rule_name}: {e}")

    # 4. Save results to the output folder
    output_file = os.path.join('output', 'results.json')
    os.makedirs('output', exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(full_report, f, indent=4)
        
    print(f"\n✅ Scan Complete! Results saved to {output_file}")
    return full_report