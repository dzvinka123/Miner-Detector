import psutil

miner_names = ["xmrig", "minerd", "ethminer", "nicehash", "lolminer"]

found_miners = []

for proc in psutil.process_iter(["pid", "name"]):
    try:
        process_name = proc.info["name"].lower()
        for miner in miner_names:
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
