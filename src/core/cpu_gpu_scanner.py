import psutil
import GPUtil
from io import StringIO


def scan_cpu(report_buffer: StringIO) -> None:
    """
    Scans the system's CPU usage and details and writes the results to the provided report buffer.

    Args:
        report_buffer (StringIO): A StringIO object used to store the CPU scan results.

    Returns:
        None
    """
    print("Scanning CPU...")
    report_buffer.write(f"CPU Usage: {psutil.cpu_percent(interval=1)}%\n")
    report_buffer.write(f"CPU Cores: {psutil.cpu_count(logical=False)}\n")
    report_buffer.write(f"Total CPU Threads: {psutil.cpu_count()}\n")


def scan_gpu(report_buffer: StringIO) -> None:
    """
    Scans the system's GPU usage and details and writes the results to the provided report buffer.

    Args:
        report_buffer (StringIO): A StringIO object used to store the GPU scan results.

    Returns:
        None
    """
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
