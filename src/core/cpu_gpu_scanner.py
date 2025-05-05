import psutil
import GPUtil


def scan_cpu(report_buffer):
    print("Scanning CPU...")
    report_buffer.write(f"CPU Usage: {psutil.cpu_percent(interval=1)}%\n")
    report_buffer.write(f"CPU Cores: {psutil.cpu_count(logical=False)}\n")
    report_buffer.write(f"Total CPU Threads: {psutil.cpu_count()}\n")


def scan_gpu(report_buffer):
    print("Scanning GPU...")
    if GPUtil.getAvailable():
        gpus = GPUtil.getGPUs()
        for gpu in gpus:
            report_buffer.write(f"GPU: {gpu.name}\n")
            report_buffer.write(f"Load: {gpu.load*100:.1f}%\n")
            report_buffer.write(
                f"Memory Used: {gpu.memoryUsed}MB / {gpu.memoryTotal}MB\n"
            )
    else:
        print("No GPUs detected.")
        report_buffer.write(f"[!] GPU: No GPUs detected.\n")
