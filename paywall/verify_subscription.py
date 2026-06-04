import os
import sys
import time
import requests

# -------------------------------------------------------------------
# WEB3 SAAS CONFIGURATION
# -------------------------------------------------------------------
# The wallet where you receive subscriptions
OWNER_WALLET = "0x9758AdAe878bD4EA0d0aa24408c56D7d4aEC29a5".lower()

# Required payment amount: 50 USDC (USDC has 6 decimals, so 50 * 10^6)
REQUIRED_AMOUNT = 50 * (10**6)

# Subscription duration in seconds (30 days)
SUBSCRIPTION_DURATION = 30 * 24 * 60 * 60

# We support Ethereum (Mainnet) and Base
NETWORKS = {
    "ethereum": {
        "api_url": "https://api.etherscan.io/api",
        "usdc_contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "env_key": "ETHERSCAN_API_KEY"
    },
    "base": {
        "api_url": "https://api.basescan.org/api",
        "usdc_contract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "env_key": "BASESCAN_API_KEY"
    }
}

def verify_subscription(user_wallet: str) -> bool:
    """
    Verifies if `user_wallet` has sent at least `REQUIRED_AMOUNT` of USDC
    to `OWNER_WALLET` within the last 30 days on either Ethereum or Base.
    """
    if not user_wallet:
        print("[PAYWALL] ❌ No wallet address provided. Access to AI Validation PRO denied.")
        return False
        
    user_wallet = user_wallet.lower()
    current_time = int(time.time())

    for network_name, config in NETWORKS.items():
        api_key = os.environ.get(config["env_key"])
        if not api_key:
            print(f"[PAYWALL] ⚠️ Warning: No API key found for {network_name} ({config['env_key']}). Skipping network.")
            continue
            
        print(f"[PAYWALL] 🔍 Checking {network_name.capitalize()} for subscription payments...")
        
        # Query ERC20 Token Transfers for the User's Wallet
        params = {
            "module": "account",
            "action": "tokentx",
            "contractaddress": config["usdc_contract"],
            "address": user_wallet,
            "page": 1,
            "offset": 100, # Check the last 100 transfers
            "startblock": 0,
            "endblock": 99999999,
            "sort": "desc",
            "apikey": api_key
        }
        
        try:
            response = requests.get(config["api_url"], params=params, timeout=10)
            data = response.json()
            
            if data.get("status") == "1" and data.get("result"):
                transactions = data["result"]
                for tx in transactions:
                    # Check if transaction is a transfer to the owner wallet
                    if tx.get("to", "").lower() == OWNER_WALLET:
                        # Check amount
                        value = int(tx.get("value", 0))
                        # Check time
                        tx_time = int(tx.get("timeStamp", 0))
                        
                        if value >= REQUIRED_AMOUNT and (current_time - tx_time) <= SUBSCRIPTION_DURATION:
                            print(f"[PAYWALL] ✅ VALID SUBSCRIPTION FOUND on {network_name.capitalize()}!")
                            print(f"          Tx Hash: {tx.get('hash')}")
                            print(f"          Amount: {value / 10**6} USDC")
                            return True
        except Exception as e:
            print(f"[PAYWALL] ❌ API Error on {network_name}: {e}")

    print(f"[PAYWALL] 🚫 No active subscription found for {user_wallet}.")
    print(f"[PAYWALL] Please send 50 USDC to {OWNER_WALLET} on Base or Ethereum.")
    return False

if __name__ == "__main__":
    wallet = os.environ.get("WALLET_ADDRESS", "")
    if verify_subscription(wallet):
        sys.exit(0) # Success
    else:
        sys.exit(1) # Paywall blocked
