import psutil
import os

from dotenv import load_dotenv

load_dotenv()

miner_names = os.getenv("MINER_NAMES", "")
MINERS = miner_names.split(",") if miner_names else []

found_miners = []

for proc in psutil.process_iter(["pid", "name"]):
    try:
        process_name = proc.info["name"].lower()
        for miner in MINERS:
            if miner not in process_name:
                found_miners.append((proc.info["pid"], proc.info["name"]))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue

if found_miners:
    print("Finds miner:")
    for pid, name in found_miners:
        print(f"PID: {pid}, name: {name}")
else:
    print("Not found!")
