<div align="center">
  <img src="https://img.icons8.com/color/144/000000/security-shield.png" alt="Security Shield" width="120" />
  
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

| Feature | 🆓 Free Tier (Slither) | 💎 PRO Tier (AI Validator) |
|---------|:---:|:---:|
| **AST-Based Structural Analysis** | ✅ | ✅ |
| **Basic Vulnerability Detection** | ✅ | ✅ |
| **Pull Request PR Comments** | ✅ | ✅ |
| **Deep AI Logical Flaw Detection** | ❌ | ✅ |
| **False-Positive Suppression (99% Accuracy)**| ❌ | ✅ |
| **Advanced MEV & Flash Loan Vectors** | ❌ | ✅ |

---

## 🚀 Quick Start (Installation)

Add the following workflow to your repository (`.github/workflows/audit.yml`) to automatically scan your smart contracts on every Pull Request:

```yaml
name: "Web3 Security Audit"
on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Solidity Security Scanner PRO
        uses: mvmax-dev/solidity-security-scanner@main
        with:
          # Optional: Specify your wallet address to unlock AI Validation PRO features!
          wallet_address: "0xYourWalletAddress"
          
        env:
          # Required for PRO verification
          ETHERSCAN_API_KEY: ${{ secrets.ETHERSCAN_API_KEY }}
          BASESCAN_API_KEY: ${{ secrets.BASESCAN_API_KEY }}
```

---

## 💎 PRO Version & Web3 Paywall (How to Upgrade)

The basic structural analysis is 100% free forever. 
However, **AI Vulnerability Validation** (which rigorously suppresses false positives and detects complex logical flaws) is secured behind a decentralized Web3 Paywall.

**To Unlock PRO (30-Day Subscription):**
1. Send exactly **50 USDC** on the **Ethereum Mainnet** or **Base Network** to the official Scanner Treasury:
   👉 `0x9758AdAe878bD4EA0d0aa24408c56D7d4aEC29a5`
2. Add the wallet address you sent the funds from to the `wallet_address` input in your GitHub workflow.
3. The Action will securely query the blockchain (via Etherscan/Basescan APIs). Once your USDC transfer is detected, the AI Validator automatically unlocks!

*No credit cards, no sign-ups, just pure Web3 automation.*

---

## 🏗️ Architecture Under the Hood

1. **Ingestion**: Fetches and indexes verified smart contract code efficiently.
2. **Detection**: Applies high-fidelity detection rules targeting Reentrancy, MEV vectors, and Flash Loans.
3. **Web3 Verification**: Instantly queries Etherscan/Basescan APIs for recent subscription transactions.
4. **AI Validation**: PRO feature that cross-references all findings to suppress false positives and output a beautiful Markdown summary directly to your GitHub PR.

---

## 🤝 Contributing & Security

We believe in securing the Web3 ecosystem together. 
Please see our [Contributing Guidelines](CONTRIBUTING.md) and [Security Policy](SECURITY.md).

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
