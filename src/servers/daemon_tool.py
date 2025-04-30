import os
import sys
import time
import atexit

from cli.cli import scan


class ScannerDaemon:
    def __init__(self, args):
        self.stdin = "/dev/null"
        self.stdout = "/tmp/mydaemon.log"
        self.stderr = "/tmp/mydaemon_err.log"
        self.pidfile = "/tmp/mydaemon.pid"
        self.args = args

    def delpid(self):
        os.remove(self.pidfile)

    def daemonize(self):
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

    def run(self):
        while True:
            scan(self.args)
            time.sleep(10)
