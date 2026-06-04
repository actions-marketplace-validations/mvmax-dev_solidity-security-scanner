<div align="center">
  
  <img src="docs/logo.png" alt="Solidity Security Scanner PRO" width="120" />

  # Solidity Security Scanner PRO

  **The #1 Automated Smart Contract Auditor for GitHub CI/CD**
  
  *From install to first vulnerability caught in < 60 seconds.*

  [![Security Scanner CI](https://github.com/mvmax-dev/solidity-security-scanner/actions/workflows/python-app.yml/badge.svg)](https://github.com/mvmax-dev/solidity-security-scanner/actions/workflows/python-app.yml)
  [![Marketplace](https://img.shields.io/badge/GitHub-Marketplace-blue)](https://github.com/marketplace/actions/automated-smart-contract-auditor-pro)
  [![Web3 Paywall](https://img.shields.io/badge/Payment-Crypto_USDC-green)](#-pro-version-hybrid-saas-paywall)
  [![Enterprise](https://img.shields.io/badge/Enterprise-B2B_Ready-purple)](#-pro-version-hybrid-saas-paywall)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Solidity](https://img.shields.io/badge/Solidity-Security-363636?logo=solidity)](https://soliditylang.org)
  [![Ethereum](https://img.shields.io/badge/Ethereum-Auditor-3C3C3D?logo=ethereum)](https://ethereum.org)
  [![Solana](https://img.shields.io/badge/Solana-Rust_Scanner-9945FF?logo=solana)](https://solana.com)

  *Web3 Security • DeFi Auditor • Reentrancy Scanner • Flash Loan Defense • Solana CPI Security • Foundry Fuzzing • Smart Contract Security Bot • Gas Optimizer • MEV Protection • Slither GitHub Action*
</div>

---

## 🚀 Welcome to the Future of Web3 Security

An advanced, open-source static analysis and **AI-powered vulnerability detection engine** specifically designed for Ethereum, Base, and Solana smart contracts. Built for Web3 security researchers, DeFi auditors, and protocol developers to proactively identify and remediate critical attack vectors.

**🔥 Time-to-First-Scan: < 60 seconds.** From installation to identifying your first critical vulnerability in under a minute.

Now available as a **Zero-Friction GitHub Action**. Automatically secure every Pull Request before it hits production!

---

## ⚡ Features & Tiers (Hybrid Billing)

| Feature | 🆓 Free Tier (Slither) | 💎 PRO Tier (Web3 Indie) | 🏢 Enterprise Tier (B2B) |
|---------|:---:|:---:|:---:|
| **AST-Based Structural Analysis** | ✅ | ✅ | ✅ |
| **Pull Request PR Comments** | ✅ | ✅ | ✅ |
| **Foundry Fuzz Testing** | ✅ | ✅ | ✅ |
| **Solana / Rust Native Support** | ✅ | ✅ | ✅ |
| **Deep AI Logical Flaw Detection** | ❌ | ✅ | ✅ |
| **False-Positive Suppression (99%)**| ❌ | ✅ | ✅ |
| **AST Gas Optimization Engine** | ❌ | ✅ | ✅ |
| **Payment Method** | Free | 50 USDC (Crypto) | Fiat / Stripe |

---

## 🚀 Quick Start (Installation)

Add the following workflow to your repository (`.github/workflows/audit.yml`). 
> **Performance Tip:** We highly recommend caching the Docker layers to bypass Rust/Foundry compilation overhead on stateless runners, reducing scan times from 5 minutes to 30 seconds!

```yaml
name: "Web3 Security Audit & Gas Optimization"
on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # Recommended: Cache Docker layers for blazing fast CI/CD
      - name: Cache Docker layers
        uses: actions/cache@v3
        with:
          path: /tmp/.buildx-cache
          key: ${{ runner.os }}-buildx-${{ github.sha }}
          restore-keys: |
            ${{ runner.os }}-buildx-

      - name: Run Solidity Security Scanner & Optimizer PRO
        uses: mvmax-dev/solidity-security-scanner@main
        with:
          # Web3 Indie License (Crypto)
          wallet_address: "0xYourWalletAddress"
          # OR Enterprise License (Fiat)
          enterprise_key: ${{ secrets.SCANNER_ENTERPRISE_KEY }}
          # Required for PR Bot Comments
          github_token: ${{ secrets.GITHUB_TOKEN }}
          
        env:
          ETHERSCAN_API_KEY: ${{ secrets.ETHERSCAN_API_KEY }}
          BASESCAN_API_KEY: ${{ secrets.BASESCAN_API_KEY }}
```

---

## 💎 PRO Version: Hybrid SaaS Paywall

We offer frictionless billing for both Indie Web3 Hackers and Traditional Web2 Enterprises.

**Option A: Web3 Indie (Decentralized Crypto Paywall)**
1. Send exactly **50 USDC** on the **Ethereum Mainnet** or **Base Network** to the official Scanner Treasury: `0x9758AdAe878bD4EA0d0aa24408c56D7d4aEC29a5`
2. Add your wallet address to the `wallet_address` input in your GitHub workflow.

**Option B: Enterprise B2B (Stripe Subscription)**
For corporate finance departments that require fiat billing, invoicing, and auto-renewals.
1. Subscribe via our Stripe Portal (Coming Soon to the Dashboard).
2. Add your license key to GitHub Secrets and pass it to the `enterprise_key` input.

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
