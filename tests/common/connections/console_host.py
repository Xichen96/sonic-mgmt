import logging
import socket
import threading

from .base_console_conn import (
    CONSOLE_SSH,
    CONSOLE_SSH_CISCO_CONFIG,
    CONSOLE_SSH_MENU_PORTS,
    CONSOLE_SSH_TO_PORT,
    CONSOLE_TELNET,
    CONSOLE_SSH_DIGI_CONFIG,
    CONSOLE_SSH_SONIC_CONFIG,
    CONSOLE_CONSERVER,
    CONSOLE_SSH_RARITAN_CONFIG,
)
from .telnet_console_conn import TelnetConsoleConn
from .ssh_console_conn import SSHConsoleConn
from .conserver_console_conn import ConserverConsoleConn
from .linecard_console_conn import LinecardConsoleConn
try:
    from netmiko.ssh_exception import NetMikoAuthenticationException
except ImportError:
    from netmiko.exceptions import NetMikoAuthenticationException

logger = logging.getLogger(__name__)

CONSOLE_LINECARD = "console_linecard"

ConsoleTypeMapper = {
    CONSOLE_TELNET: TelnetConsoleConn,
    CONSOLE_SSH: SSHConsoleConn,
    CONSOLE_SSH_MENU_PORTS: SSHConsoleConn,
    CONSOLE_SSH_TO_PORT: SSHConsoleConn,
    CONSOLE_SSH_DIGI_CONFIG: SSHConsoleConn,
    CONSOLE_SSH_SONIC_CONFIG: SSHConsoleConn,
    CONSOLE_SSH_CISCO_CONFIG: SSHConsoleConn,
    CONSOLE_CONSERVER: ConserverConsoleConn,
    CONSOLE_LINECARD: LinecardConsoleConn,
    CONSOLE_SSH_RARITAN_CONFIG: SSHConsoleConn,
}


def ConsoleHost(console_type,
                console_host,
                console_port,
                sonic_username,
                sonic_password,
                console_username=None,
                console_password=None,
                console_device=None,
                console_direct_ssh_port=None,
                timeout_s=100,
                supervisor_ip=None,
                linecard_number=None,
                slot_num=None,
                hwsku=None,
                attach_only=False,
                sock=None):
    if console_type not in ConsoleTypeMapper:
        raise ValueError("console type {} is not supported yet".format(console_type))
    if attach_only and not issubclass(ConsoleTypeMapper[console_type], (SSHConsoleConn, TelnetConsoleConn)):
        raise ValueError("attach_only is not supported for console type {}".format(console_type))
    params = {
        "console_host": console_host,
        "console_port": console_port,
        "console_type": console_type,
        "sonic_username": sonic_username,
        "sonic_password": sonic_password,
        "console_username": console_username,
        "console_password": console_password,
        "console_device": console_device,
        "timeout": timeout_s
    }
    if attach_only:
        params["attach_only"] = True
    # An open connection to the console server for netmiko to use instead of opening its own
    if sock is not None:
        params["sock"] = sock

    # Add linecard-specific parameters if provided
    if supervisor_ip is not None:
        params["supervisor_ip"] = supervisor_ip
    if linecard_number is not None:
        params["linecard_number"] = linecard_number
    if slot_num is not None:
        params["slot_num"] = slot_num
    if hwsku is not None:
        params["hwsku"] = hwsku
    if console_direct_ssh_port is not None:
        params["direct_ssh_port"] = console_direct_ssh_port

    return ConsoleTypeMapper[console_type](**params)


class ConsoleLine(object):
    """
    A console line on a console server. Like duthost for the management port, it keeps the
    console settings and only connects when asked.

    disconnect() can be called from any thread. It closes the current connection, also one that
    is still being set up, and stops any further attempts. The line is quiet afterwards until
    connect() is called again.
    """

    def __init__(self, attempts=1, retry_interval=0, **console_host_args):
        self.console_host_args = console_host_args
        self.attempts = attempts
        self.retry_interval = retry_interval
        self.connection = None
        self._sock = None
        self._lock = threading.Lock()
        self._stopped = threading.Event()

    def connect(self):
        """
        Connect to the console line, trying up to self.attempts times.

        Returns the connection, or None if disconnect() was called meanwhile.
        """
        self._stopped.clear()
        for attempt in range(1, self.attempts + 1):
            try:
                return self._connect_once()
            except Exception as e:
                if self._stopped.is_set():
                    return None
                logger.warning(f"Attempt {attempt}/{self.attempts} failed: {e}")
            # Back off so rapid retries do not trip the DUT serial-getty start limit. disconnect() ends the wait.
            if attempt < self.attempts and self._stopped.wait(self.retry_interval):
                return None
        raise Exception("Failed to set up connection to console port. See warning logs for details.")

    def disconnect(self):
        """Close the current connection, also one still being set up, and stop any further attempts."""
        with self._lock:
            self._stopped.set()
            sock, self._sock = self._sock, None
            connection, self.connection = self.connection, None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        if connection is not None:
            connection.disconnect()

    def _connect_once(self):
        args = self.console_host_args
        if not issubclass(ConsoleTypeMapper[args["console_type"]], SSHConsoleConn):
            return self._keep(ConsoleHost(**args))
        # Open the connection to the console server here, so disconnect() can close it while the
        # logins are still in progress. netmiko closes it after a rejected password, so each
        # password gets its own connection.
        passwords = args.get("console_password") or [None]
        for i, password in enumerate(passwords):
            sock = socket.create_connection((args["console_host"], args.get("console_direct_ssh_port") or 22),
                                            timeout=10)
            with self._lock:
                if self._stopped.is_set():
                    sock.close()
                    return None
                self._sock = sock
            try:
                return self._keep(ConsoleHost(**dict(args, console_password=[password], sock=sock)))
            except NetMikoAuthenticationException:
                if i == len(passwords) - 1:
                    raise
            finally:
                with self._lock:
                    self._sock = None

    def _keep(self, connection):
        with self._lock:
            if not self._stopped.is_set():
                self.connection = connection
                return connection
        connection.disconnect()
        return None
