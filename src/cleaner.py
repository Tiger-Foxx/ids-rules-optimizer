import re
from tqdm import tqdm

class RuleCleaner:
    def __init__(self):
        # 1. State/Memory keywords (ignored)
        self.STATEFUL_KEYWORDS = [
            "flowbits",
            "threshold",
            "detection_filter",
            "stream_size",
            "tag",
            "rate_filter",
        ]

        # 2. Complex logic keywords (ignored for PoC)
        self.COMPLEX_LOGIC_KEYWORDS = [
            "byte_test",
            "byte_jump",
            "byte_extract",
            "ssl_state",
            "dsize",
            "isdataat"
        ]
        
        # 3. Blacklisted SIDs
        self.BLACKLISTED_SIDS = [
            "51642",  # Block curl User-Agent
        ]

    def analyze_rule(self, line):
        """
        Smart rule analysis.
        Returns: (Keep/Reject, Reason)
        """
        line_lower = line.lower().strip()
        
        # 1. Ignore comments
        if not line_lower or line_lower.startswith('#'):
            return False, "Ignored"

        # 2. Blacklisted SIDs
        for sid in self.BLACKLISTED_SIDS:
            if f"sid:{sid};" in line_lower:
                return False, f"Blacklisted (sid:{sid})"

        # 3. Stateful keywords
        for kw in self.STATEFUL_KEYWORDS:
            if kw in line_lower:
                return False, f"Stateful ({kw})"

        # 4. Complex logic
        for kw in self.COMPLEX_LOGIC_KEYWORDS:
            if kw in line_lower:
                return False, f"Too Complex ({kw})"

        return True, "OK"

    def process_file(self, input_path, output_path):
        print(f"[*] Starting smart cleaning on: {input_path}")
        
        stats = {
            "total": 0,
            "kept": 0,
            "rejected": 0,
            "details": {}
        }
        kept_rules = []

        with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
            stats["total"] = len(lines)

            for line in tqdm(lines, desc="Analyzing rules", unit="rule"):
                keep, reason = self.analyze_rule(line)
                
                if keep:
                    stats["kept"] += 1
                    kept_rules.append(line)
                else:
                    if reason != "Ignored":
                        stats["rejected"] += 1
                        cat = reason.split('(')[0].strip()
                        stats["details"][cat] = stats["details"].get(cat, 0) + 1

        with open(output_path, 'w', encoding='utf-8') as f_out:
            f_out.writelines(kept_rules)

        self._print_stats(stats, output_path)

    def _print_stats(self, stats, output_path):
        print("\n" + "="*60)
        print("CLEANING REPORT")
        print("="*60)
        print(f"Total read        : {stats['total']}")
        print(f"REJECTED (Stats)  : {stats['details'].get('Stateful', 0)} rules")
        print(f"REJECTED (Complex): {stats['details'].get('Too Complex', 0)} rules")
        print("-" * 40)
        print(f"[OK] KEPT         : {stats['kept']} rules")
        print("="*60)