import os
import hashlib
import time

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "chain.log")

def create_block(data):
    try:
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)

        timestamp = str(time.time())
        block_data = data + timestamp
        block_hash = hashlib.sha256(block_data.encode()).hexdigest()

        with open(LOG_FILE, "a") as f:
            f.write(f"{timestamp} | {data} | {block_hash}\n")

    except Exception as e:
        print(f"[BLOCK ERROR] {e}")