import os
import sys
import time
import atexit

from services.cli import scan


class ScannerDaemon:
    """
    A class that runs a scanner as a daemon, performing periodic scans based on given intervals.

    Attributes:
        stdin (str): The input file descriptor.
        stdout (str): The output file descriptor.
        stderr (str): The error file descriptor.
        pidfile (str): The file path for the daemon's PID file.
        duration (int): The duration for which the daemon runs, in seconds.
        interval (int): The interval between scans, in seconds.
        network (str, optional): The network interface to scan, if any.
    """

    def __init__(self, duration: int, interval: int, network: str = None) -> None:
        """
        Initializes the ScannerDaemon instance.

        Args:
            duration (int): The duration for which the daemon should run, in seconds.
            interval (int): The interval between scans, in seconds.
            network (str, optional): The network interface to scan, if any.
        """
        self.stdin = "/dev/null"
        self.stdout = "/tmp/scan_daemon.log"
        self.stderr = "/tmp/scan_daemon_err.log"
        self.pidfile = "/tmp/scan_daemon.pid"
        self.duration = duration
        self.interval = interval
        self.network = network

    def delpid(self) -> None:
        """
        Removes the PID file when the daemon exits.

        Returns:
            None
        """
        os.remove(self.pidfile)

    def daemonize(self) -> None:
        """
        Turns the process into a daemon by forking twice and detaching from the terminal.

        Returns:
            None
        """
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f"Fork 1 failed: {e.errno} ({e.strerror})\n")
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write(f"Fork 2 failed: {e.errno} ({e.strerror})\n")
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(self.stdin, "r")
        so = open(self.stdout, "a+")
        se = open(self.stderr, "a+", buffering=1)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        with open(self.pidfile, "w+") as f:
            f.write(f"{pid}\n")

    def run(self) -> None:
        """
        Runs the daemon, executing the scan periodically for the specified duration and interval.

        Returns:
            None
        """
        start_time = time.time()
        duration = self.duration
        interval = self.interval

        while time.time() - start_time < duration:
            scan(proc=True, gpu=True, cpu=True, logs=True, network=self.network)
            time.sleep(interval)
        self.delpid()
