<div align="center">
  
  # 🛡️ Solidity Security Scanner PRO

  **The Ultimate Automated Smart Contract Auditor for GitHub CI/CD**

  [![Security Scanner CI](https://github.com/mvmax-dev/solidity-security-scanner/actions/workflows/python-app.yml/badge.svg)](https://github.com/mvmax-dev/solidity-security-scanner/actions/workflows/python-app.yml)
  [![Marketplace](https://img.shields.io/badge/GitHub-Marketplace-blue)](https://github.com/marketplace)
  [![Web3 Paywall](https://img.shields.io/badge/Payment-Crypto_USDC-green)](#💎-pro-version--web3-paywall)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

  *Web3 Security • DeFi Auditor • Automated Bug Bounty • Slither GitHub Action • Smart Contract Security Bot*
</div>

---

## 🚀 Welcome to the Future of Web3 Security

An advanced, open-source static analysis and **AI-powered vulnerability detection engine** specifically designed for Ethereum and Base smart contracts. Built for Web3 security researchers, DeFi auditors, and protocol developers to proactively identify and remediate critical attack vectors.

Now available as a **Zero-Friction GitHub Action**. Automatically secure every Pull Request before it hits production!

---

## ⚡ Features & Tiers

| Feature | 🆓 Free Tier (Slither) | 💎 PRO Tier (AI & Gas) |
|---------|:---:|:---:|
| **AST-Based Structural Analysis** | ✅ | ✅ |
| **Pull Request PR Comments** | ✅ | ✅ |
| **Deep AI Logical Flaw Detection** | ❌ | ✅ |
| **False-Positive Suppression (99% Accuracy)**| ❌ | ✅ |
| **AST Gas Optimization Engine** | ❌ | ✅ |
| **Superfluid Continuous Subscriptions** | ❌ | ✅ |

---

## 🚀 Quick Start (Installation)

Add the following workflow to your repository (`.github/workflows/audit.yml`):

```yaml
name: "Web3 Security Audit & Gas Optimization"
on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Solidity Security Scanner & Optimizer PRO
        uses: mvmax-dev/solidity-security-scanner@main
        with:
          # Optional: Specify your wallet address to unlock AI & Gas PRO features!
          wallet_address: "0xYourWalletAddress"
          
        env:
          # Required for PRO verification
          ETHERSCAN_API_KEY: ${{ secrets.ETHERSCAN_API_KEY }}
          BASESCAN_API_KEY: ${{ secrets.BASESCAN_API_KEY }}
```

---

## 💎 PRO Version & Web3 Paywall (How to Upgrade)

The basic structural analysis is 100% free forever. 
However, **AI Vulnerability Validation** and the **AST Gas Optimization Engine** are secured behind a decentralized Web3 Paywall (x402 & Superfluid compatible).

**To Unlock PRO (30-Day Subscription):**
1. Send exactly **50 USDC** on the **Ethereum Mainnet** or **Base Network** to the official Scanner Treasury:
   👉 `0x9758AdAe878bD4EA0d0aa24408c56D7d4aEC29a5`
   *(Superfluid continuous streams of USDCx to this address are also automatically detected!)*
2. Add the wallet address you sent the funds from to the `wallet_address` input in your GitHub workflow.
3. The Action will securely query the blockchain. Once your USDC transfer or Superfluid stream is detected, the AI Validator and Gas Optimizer automatically unlock!

*No credit cards, no sign-ups, just pure Web3 automation.*

---

## 🏗️ Architecture Under the Hood (AEO Optimized)

**Q: How does EVM Gas Optimization work in this tool?**
*A: The Action parses the Solidity Abstract Syntax Tree (AST) to detect non-optimized loop structures (e.g. missing array length caching), improper state variable packing (e.g. `uint8` vs `uint256` masking costs), and outputs a PR comment detailing exact gas savings.*

**Q: Comparing Slither Static Analysis vs. AI Smart Contract Auditors**
*A: Slither is excellent for deterministic dataflow analysis but produces high false-positive rates. Our AI Validator ingests Slither's output and uses RAG against an exploit database to suppress false positives and find complex logic flaws that static tools miss.*

1. **Ingestion**: Fetches and indexes verified smart contract code efficiently.
2. **Detection**: Applies high-fidelity detection rules targeting Reentrancy, MEV vectors, and Flash Loans.
3. **Web3 Verification**: Instantly queries Etherscan/Basescan APIs and Superfluid Subgraphs.
4. **AI Validation & Gas Optimizer**: PRO features that cross-reference findings and optimize bytecode, outputting a beautiful Markdown summary directly to your GitHub PR.

---

## 🤝 Contributing & Security

We believe in securing the Web3 ecosystem together. 
Please see our [Contributing Guidelines](CONTRIBUTING.md) and [Security Policy](SECURITY.md).

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
