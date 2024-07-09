from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from enum import Enum
from subprocess import PIPE, Popen
from tempfile import gettempdir
from threading import Lock

import psutil
from docopt import docopt

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setFormatter(
    logging.Formatter(
        "\r\n%(asctime)s OpenVPN: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
)
logger.addHandler(console_handler)


PID_FILE = f"{gettempdir()}/openvpnclient.pid"


class Status(Enum):
    CONNECTED = (1,)
    DISCONNECTED = (2,)
    CONNECTION_FAILED = (3,)
    IDLE = (4,)
    USER_CANCELLED = (5,)
    CONNECTION_TIMEOUT = (6,)


class OpenVPNClient:
    """Module for managing an OpenVPN connection."""

    status: Status = Status.IDLE
    proc: Popen
    stderr: str = ""
    stdout: str = ""

    def __init__(self, ovpn_file: str, connect_timeout: int = 5) -> None:
        """Initialize the OpenVPN client

        Args:
            ovpn_file (str): The OpenVPN configuration file
            connect_timeout (int): The connection attempt limit in seconds

        Raises:
            ValueError: If connect_timeout is less than, or equal to, 0
        """
        if connect_timeout <= 0:
            raise ValueError("Connection timeout must be at least 1 second")
        self.connect_timeout = connect_timeout
        self.ovpn_dir = os.path.dirname(ovpn_file)
        self.ovpn_file = ovpn_file

    def __enter__(self) -> OpenVPNClient:
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.disconnect()

    def connect(self, stay_alive_on_exit: bool = False) -> None:
        """Connect to the OpenVPN server using the provided configuration file

        Args:
            stay_alive_on_exit (bool): If True, the connection will not be
            terminated when the script is exited

        Raises:
            NotADirectoryError: If the configuration file's directory is not found
            FileNotFoundError: If the configuration file is not found
            ConnectionError: If the client is already connected
            TimeoutError: If the connection attempt times out
        """
        if not os.path.exists(self.ovpn_dir):
            raise NotADirectoryError(f"Directory '{self.ovpn_dir}' not found")
        if not os.path.exists(self.ovpn_file):
            raise FileNotFoundError(f"File '{self.ovpn_file}' not found")
        if OpenVPNClient._get_pid() != -1:
            raise ConnectionError("Already connected")

        lock = Lock()
        lock.acquire()

        def on_connected(*_) -> None:
            self.status = Status.CONNECTED
            lock.release()

        def on_connect_timeout(*_) -> None:
            self.status = Status.CONNECTION_TIMEOUT
            lock.release()

        def on_user_cancelled(*_) -> None:
            if self.status is Status.CONNECTED:
                OpenVPNClient.disconnect()
            else:
                lock.release()
            self.status = Status.USER_CANCELLED

        signal.signal(signal.SIGUSR1, on_connected)
        signal.signal(signal.SIGINT, on_user_cancelled)
        timer = threading.Timer(self.connect_timeout, on_connect_timeout)
        timer.start()

        cmd = [
            "openvpn",
            "--cd", self.ovpn_dir,
            "--config", self.ovpn_file,
            "--dev", "tun_ovpn",
            "--connect-retry-max", "3",
            "--connect-timeout", str(self.connect_timeout),
            "--script-security", "2",
            "--route-delay", "1",
            "--route-up", f"{sys.executable} -c 'import os, signal; os.kill({os.getpid()}, signal.SIGUSR1)'"
        ]
        self.proc = Popen(cmd, stderr=PIPE, stdout=PIPE)

        OpenVPNClient._register_pid(self.proc.pid)

        if not stay_alive_on_exit:

            def proc_exited() -> None:
                returncode = self.proc.wait()
                if returncode != 0:
                    self.status = Status.CONNECTION_FAILED
                    stderr = (
                        self.proc.stderr.read().decode() if self.proc.stderr else ""
                    )
                    stdout = (
                        self.proc.stdout.read().decode() if self.proc.stdout else ""
                    )
                    msg = f"""\n
                        \rOpenVPN process failed with exit code {returncode}\n
                        \rstdout: {stdout}
                        \rstderr: {stderr}
                    """
                    raise ConnectionRefusedError(msg)
                else:
                    self.status = Status.DISCONNECTED

            self.on_exit_thread = threading.Thread(target=proc_exited)
            self.on_exit_thread.start()

            def excepthook(args) -> None:
                lock.release()
                raise args.exc_type(args.exc_value)

            threading.excepthook = lambda args: excepthook(args)

        with lock:
            timer.cancel()
            signal.signal(signal.SIGUSR1, signal.SIG_IGN)
            if self.status is Status.CONNECTED:
                logger.info("OpenVPN connection successful")
            elif self.status is Status.CONNECTION_TIMEOUT:
                OpenVPNClient.disconnect()
                raise TimeoutError(f"Did not connect in {self.connect_timeout}s")
            elif self.status is Status.USER_CANCELLED:
                OpenVPNClient.disconnect()
            elif self.status is Status.CONNECTION_FAILED:
                OpenVPNClient._remove_pid_file()
                raise ConnectionRefusedError("OpenVPN connection failed")

    @staticmethod
    def _register_pid(pid: int) -> None:
        """Store the PID of the active OpenVPN process

        Args:
            pid (int): The process ID
        """
        with open(PID_FILE, "w") as f:
            f.write(str(pid))

    @staticmethod
    def _get_pid() -> int:
        """Retrieve the PID of the active OpenVPN process

        Returns:
            int: The process ID
        """
        try:
            with open(PID_FILE, "r") as f:
                try:
                    pid = int(f.read().strip())
                    return pid
                except ValueError as e:
                    logger.error(f"PID in '{PID_FILE}' is not an integer")
                    raise e
        except FileNotFoundError:
            return -1

    @staticmethod
    def _remove_pid_file() -> None:
        """Remove the PID file"""
        os.remove(PID_FILE)

    @staticmethod
    def disconnect() -> None:
        """Disconnect the current OpenVPN connection

        Raises:
            ProcessLookupError: If the PID file is not found or the PID file is corrupt
            TimeoutError: If the process doesn't terminate in 5 seconds
        """
        pid = OpenVPNClient._get_pid()
        if pid == -1:
            raise ProcessLookupError("Did not find an ongoing connection")
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            OpenVPNClient._remove_pid_file()
            raise ProcessLookupError(
                f"Corrupt PID file, PID {pid} doesn't exist, removed file"
            )
        proc.terminate()  # 'explicit-exit-notify' requires SIGTERM
        timeout = 5
        try:
            psutil.wait_procs([proc], timeout=timeout)
            OpenVPNClient._remove_pid_file()
            logger.info("Process terminated")
        except TimeoutError:  # unable to force slower termination
            proc.kill()
            raise TimeoutError(f"Process didn't terminate in {timeout}, killed instead")


usage = """
    Usage:
        openvpnclient.py --config=<config_file>
        openvpnclient.py --disconnect

    Options:
        -h --help     Show this help message
        --config=<config_file>   Configuration file (.ovpn)
        --disconnect   Disconnect ongoing connection
"""
if __name__ == "__main__":
    args = docopt(usage)

    if args["--disconnect"]:
        OpenVPNClient.disconnect()
    elif args["--config"]:
        config_file = args["--config"]
        OpenVPNClient(config_file).connect(stay_alive_on_exit=True)
    else:
        print(usage)
        sys.exit(1)
