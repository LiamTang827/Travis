import os
import requests
from datetime import datetime, timedelta, timezone
import pandas as pd
import time
from dotenv import load_dotenv

load_dotenv()

# Etherscan API Key
api_key = os.getenv("ETHERSCAN_API_KEY", "")

# Contract address
contract_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"  # USDT

offset = 10000  # Max records per request

# Define time range
start_date = datetime(2022, 3, 16, 0, 0, 0, tzinfo=timezone.utc)
end_date = datetime(2022, 3, 31, 12, 0, 0, tzinfo=timezone.utc)

# Store results
all_transactions = []

while start_date < end_date:
    if start_date.date() <= datetime(2022, 5, 21, tzinfo=timezone.utc).date():
        time_interval = timedelta(hours=0.5)
    elif start_date.date() <= datetime(2022, 11, 1, tzinfo=timezone.utc).date():
        time_interval = timedelta(hours=6)
    elif start_date.date() <= datetime(2024, 11, 2, tzinfo=timezone.utc).date():
        time_interval = timedelta(days=5)
    else:
        time_interval = timedelta(days=1)

    next_date = start_date + time_interval
    if next_date > end_date:
        next_date = end_date

    print(f"Fetching data from {start_date.isoformat()} to {next_date.isoformat()}...")

    start_timestamp = int(start_date.timestamp())
    end_timestamp = int(next_date.timestamp())

    # Get block range
    start_block_url = f"https://api.etherscan.io/api?module=block&action=getblocknobytime&timestamp={start_timestamp}&closest=after&apikey={api_key}"
    end_block_url = f"https://api.etherscan.io/api?module=block&action=getblocknobytime&timestamp={end_timestamp}&closest=before&apikey={api_key}"
    
    start_block = requests.get(start_block_url).json()['result']
    end_block = requests.get(end_block_url).json()['result']

    # Build txlist query
    url = (
        f"https://api.etherscan.io/api?module=account&action=txlist"
        f"&address={contract_address}&startblock={start_block}&endblock={end_block}"
        f"&offset={offset}&sort=asc&apikey={api_key}"
    )

    response = requests.get(url)
    time.sleep(0.2)

    if response.status_code == 200:
        data = response.json()

        if data["status"] == "1":
            transactions = data["result"]
            num_transactions = len(transactions)
            print(f"Retrieved {num_transactions} transactions.")

            if num_transactions >= offset:
                original_interval = time_interval
                time_interval = max(time_interval / 2, timedelta(minutes=10))
                print(f"Reached tx limit. Reducing interval from {original_interval} to {time_interval}.")
                continue

            for tx in transactions:
                if tx['to'].lower() == contract_address.lower():
                    try:
                        tx_date = datetime.fromtimestamp(int(tx['timeStamp']), timezone.utc)
                        input_data = tx['input']
                        params_data = input_data[10:] if input_data.startswith("0x") else input_data[8:]
                        method_id = input_data[:10]

                        if method_id == "0xa9059cbb" and len(params_data) >= 128:
                            # transfer(address, uint256)
                            claimed_amount = int(params_data[64:128], 16) / 10**6

                        elif method_id == "0x23b872dd" and len(params_data) >= 192:
                            # transferFrom(address, address, uint256)
                            claimed_amount = int(params_data[128:192], 16) / 10**6

                        else:
                            claimed_amount = None

                        all_transactions.append({
                            "Transaction Hash": tx['hash'],
                            "Date Time (UTC)": tx_date.replace(tzinfo=None),
                            "From": tx['from'],
                            "To": tx['to'],
                            "Value (ETH)": int(tx['value']) / (10 ** 18),
                            "Gas Used": int(tx['gasUsed']),
                            "Gas Price (Gwei)": int(tx['gasPrice']) / (10 ** 9),
                            "Input": tx['input'],
                            "Claimed Amount": claimed_amount,
                        })
                    except Exception as e:
                        print(f"Error parsing transaction {tx['hash']}: {e}")

        elif data["status"] == "0" and data["message"] == "No transactions found":
            print("No transactions found in this interval.")
        else:
            print(f"Error: {data['message']}")
            time.sleep(1)
    else:
        print(f"HTTP Error: {response.status_code}")
        time.sleep(1)

    start_date = next_date

print("Total transactions collected:", len(all_transactions))

if all_transactions:
    df = pd.DataFrame(all_transactions)
    df.to_excel("USDT_22.3.2_transactions_new_token.xlsx", index=False)
    print("Data exported to USDT_22.3.2_transactions_new_token.xlsx")
else:
    print("No matching transactions found.")
