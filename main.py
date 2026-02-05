import os
import argparse
from src.content_engine import ContentEngine
from src.exporter import Exporter
from src.parser import SnortParser
from src.cleaner import RuleCleaner
from src.ip_engine import IPEngine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(BASE_DIR, 'inputs')
OUTPUT_DIR = os.path.join(BASE_DIR, 'outputs')

def main():
    arg_parser = argparse.ArgumentParser(description="Network Rules Optimizer")
    arg_parser.add_argument('--rules', type=str, required=True, help="Filename in inputs/ folder")
    arg_parser.add_argument('--test-mode', action='store_true', 
                           help="Test mode: $EXTERNAL_NET = any")
    args = arg_parser.parse_args()

    input_file = os.path.join(INPUT_DIR, args.rules)
    clean_file = os.path.join(OUTPUT_DIR, 'cleaned_baseline.rules')

    if not os.path.exists(input_file):
        print(f"[ERROR] File not found: {input_file}")
        return

    # Phase 1: Cleaning
    print(">>> PHASE 1: CLEANING & FILTERING")
    cleaner = RuleCleaner()
    cleaner.process_file(input_file, clean_file)
    

    print("\n>>> Ready for PHASE 2: Parsing & Modeling")
    
    print("\n>>> PHASE 2: PARSING & MODELING")
    snort_parser = SnortParser(test_mode=args.test_mode)
    rules_objects = snort_parser.parse_file(clean_file)
    
    print(f"Parsed rules: {len(rules_objects)}")
    
    for r in rules_objects:
        if r.id == 144:
            print(f"\n[DEBUG] Rule SID 144 parsed:")
            print(f"  Proto: {r.proto}")
            print(f"  Dst Port: {r.dst_ports}")
            print(f"  Flow: {r.direction}, Established={r.established}")
            print(f"  Patterns: {len(r.patterns)}")
            for p in r.patterns:
                type_p = "PCRE" if p.is_regex else "CONTENT"
                print(f"    - {type_p}: {p.string_val}")
            break
    
    # Phase 3: Dimensional Reduction (IP/Port merging)
    print("\n>>> PHASE 3: DIMENSIONAL REDUCTION (IP/Ports)")
    ip_opt = IPEngine()
    fw_rules, deep_rules = ip_opt.optimize(rules_objects)
    
    total_before = len(rules_objects)
    total_after = len(fw_rules) + len(deep_rules)
    reduction = total_before - total_after
    
    print(f"Pure Firewall rules (-> iptables) : {len(fw_rules)}")
    print(f"Inspection rules (-> Hyperscan)   : {len(deep_rules)}")
    print(f"------------------------------------------------")
    print(f"Total rules after IP merging      : {total_after}")
    print(f"Initial reduction                 : -{reduction} rules (duplicates/merges)")

    # Phase 4: Semantic Content Optimization
    print("\n>>> PHASE 4: SEMANTIC CONTENT OPTIMIZATION")
    content_opt = ContentEngine()
    final_inspection_rules = content_opt.optimize(deep_rules)
    
    final_total = len(fw_rules) + len(final_inspection_rules)
    total_reduction = total_before - final_total
    percent = (total_reduction / total_before) * 100
    
    print("\n" + "="*50)
    print("OPTIMIZATION SUMMARY")
    print("="*50)
    print(f"Initial rules         : {total_before}")
    print(f"Final rules           : {final_total}")
    print(f"  - Pure Firewall     : {len(fw_rules)} (-> iptables)")
    print(f"  - Deep Inspection   : {len(final_inspection_rules)} (-> Hyperscan)")
    print(f"TOTAL GAIN            : {total_reduction} rules removed (-{percent:.1f}%)")
    print("="*50)
    
    # Phase 5: Export
    print("\n>>> PHASE 5: EXPORT")
    exporter = Exporter(OUTPUT_DIR)
    exporter.export_all(fw_rules, final_inspection_rules)
    
    print("\n" + "="*50)
    print("SUCCESS: PREPROCESSING COMPLETE")
    print(f"Artifacts available in: {OUTPUT_DIR}")
    print("="*50)

if __name__ == "__main__":
    main()