import os
import re
from typing import Dict, List, Any

class GasOptimizer:
    def __init__(self, workspace: str):
        self.workspace = workspace
        self.gas_findings = []

    def optimize_contract(self, contract_path: str) -> Dict[str, Any]:
        """Runs heuristic analysis to find gas optimization opportunities."""
        self.gas_findings = []  # Reset findings for each contract
        if not os.path.exists(contract_path):
            return {"status": "error", "message": "File not found"}
            
        with open(contract_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        total_gas_saved = 0
        
        for idx, line in enumerate(lines):
            line_num = idx + 1
            # 1. Loop Length Caching
            if re.search(r'for\s*\([^;]+;\s*[^;]+\.length\s*;', line):
                self.gas_findings.append({
                    "line": line_num,
                    "issue": "Uncached Array Length in Loop",
                    "recommendation": "Cache array length in a local variable before the loop to save ~100 gas per iteration.",
                    "gas_saved_est": 100
                })
                total_gas_saved += 100
            
            # 2. Post-increment in loops
            if re.search(r'for\s*\([^;]+;\s*[^;]+;\s*[a-zA-Z0-9_]+\+\+\s*\)', line):
                self.gas_findings.append({
                    "line": line_num,
                    "issue": "Post-increment used in loop",
                    "recommendation": "Use pre-increment (++i) instead of post-increment (i++) to save ~5 gas per iteration.",
                    "gas_saved_est": 5
                })
                total_gas_saved += 5
                
            # 3. uint8 memory variables
            if re.search(r'memory\s+uint8\s+', line) or re.search(r'uint8\s+[a-zA-Z0-9_]+\s*=\s*', line):
                if '[]' not in line and 'mapping' not in line:
                    self.gas_findings.append({
                        "line": line_num,
                        "issue": "Sub-word memory variable",
                        "recommendation": "Using uint8 in memory costs MORE gas due to EVM 32-byte word masking. Use uint256.",
                        "gas_saved_est": 25
                    })
                    total_gas_saved += 25

            # 4. Calldata vs Memory for external functions
            if re.search(r'function\s+\w+\s*\([^)]*\bmemory\b[^)]*\)\s*(external|public)', line):
                self.gas_findings.append({
                    "line": line_num,
                    "issue": "Memory parameter in external function",
                    "recommendation": "Use 'calldata' instead of 'memory' for external function parameters to save gas on copy operations.",
                    "gas_saved_est": 200
                })
                total_gas_saved += 200

            # 5. Constants that should be immutable
            if re.search(r'(public|private|internal)\s+(address|uint256|bytes32)\s+\w+\s*=\s*', line):
                if 'constant' not in line and 'immutable' not in line:
                    self.gas_findings.append({
                        "line": line_num,
                        "issue": "State variable could be immutable",
                        "recommendation": "If this variable is only set in the constructor, mark it as 'immutable' to save ~2100 gas per access.",
                        "gas_saved_est": 2100
                    })
                    total_gas_saved += 2100

            # 6. Unchecked arithmetic opportunities
            if re.search(r'\b(i\s*\+\+|i\s*\+=\s*1)\b', line) and 'unchecked' not in line:
                if 'for' not in line:  # Skip loop counters already caught
                    self.gas_findings.append({
                        "line": line_num,
                        "issue": "Safe arithmetic without unchecked block",
                        "recommendation": "Wrap safe increment operations in 'unchecked {}' block to save ~120 gas (Solidity >=0.8.0).",
                        "gas_saved_est": 120
                    })
                    total_gas_saved += 120

        return {
            "status": "success",
            "findings_count": len(self.gas_findings),
            "estimated_gas_saved": f"{total_gas_saved} - {total_gas_saved * 10} Gas",
            "findings": self.gas_findings
        }

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        optimizer = GasOptimizer(os.getcwd())
        res = optimizer.optimize_contract(sys.argv[1])
        print(res)
