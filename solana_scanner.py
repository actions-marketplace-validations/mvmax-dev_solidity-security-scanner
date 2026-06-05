import os
import subprocess
import logging
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

class SolanaScanner:
    def __init__(self, workspace: str):
        self.workspace = workspace
        self.is_solana = self._detect_solana()

    def _detect_solana(self) -> bool:
        # Check for Anchor or Cargo
        return os.path.exists(os.path.join(self.workspace, "Anchor.toml")) or \
               os.path.exists(os.path.join(self.workspace, "Cargo.toml"))

    def scan(self) -> Dict[str, Any]:
        if not self.is_solana:
            return {"status": "skipped", "reason": "Not a Solana/Rust project"}

        logger.info("Solana/Rust project detected. Running Cargo Audit and static checks...")
        
        findings = []
        try:
            # 1. Run cargo audit
            audit_result = subprocess.run(
                ["cargo", "audit", "--json"],
                cwd=self.workspace,
                capture_output=True,
                text=True,
                timeout=120  # 2 minutes max
            )
            
            # Simple check
            if audit_result.returncode != 0:
                findings.append({
                    "issue": "Vulnerable dependencies found via Cargo Audit.",
                    "severity": "High",
                    "details": "Update dependencies in Cargo.toml."
                })
                
            # 2. Heuristic checks for missing signer/owner checks in Solana
            rust_files = []
            for root, _, files in os.walk(self.workspace):
                for f in files:
                    if f.endswith(".rs"):
                        rust_files.append(os.path.join(root, f))
                        
            for file_path in rust_files:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if "AccountInfo" in content and ".is_signer" not in content and "#[account(signer)]" not in content:
                        findings.append({
                            "issue": "Potential Missing Signer Check",
                            "severity": "Critical",
                            "file": os.path.relpath(file_path, self.workspace),
                            "details": "Found AccountInfo usage without explicit is_signer validation."
                        })
                        
            return {
                "status": "success",
                "findings_count": len(findings),
                "findings": findings
            }

        except Exception as e:
            logger.error(f"Solana scanner failed: {e}")
            return {"status": "error", "reason": str(e)}
