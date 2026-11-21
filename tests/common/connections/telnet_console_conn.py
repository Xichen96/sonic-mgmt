import time
import re
from .base_console_conn import BaseConsoleConn
try:
    from netmiko.ssh_exception import NetMikoAuthenticationException
except ImportError:
    from netmiko.exceptions import NetMikoAuthenticationException

# Reads, and the pause between them, while a Cisco device leaves its initial configuration dialog.
CISCO_SETUP_DIALOG_MAX_READS = 15
CISCO_SETUP_DIALOG_WAIT_S = 2
LOGIN_FAILURE_PATTERN = r".*incorrect"
# Pause between successive reads and writes while driving a login.
READ_INTERVAL_S = 0.5
# Pause for the DUT to react to a login step (start, username, failed login).
RESPONSE_WAIT_S = 1
# telnet_login defaults. The delay factor multiplies the login waits; netmiko raises it to
# its global delay factor.
DEFAULT_DELAY_FACTOR = 1
DEFAULT_LOGIN_MAX_LOOPS = 20
DEFAULT_LOGIN_PRI_PROMPT_TERMINATOR = r".*# "
DEFAULT_LOGIN_ALT_PROMPT_TERMINATOR = r".*\$ "
DEFAULT_LOGIN_USERNAME_PATTERN = r"(?:user:|username|login|user name)"
DEFAULT_LOGIN_PWD_PATTERN = r"assword"


class TelnetConsoleConn(BaseConsoleConn):
    def __init__(self, **kwargs):
        # Attach to the console line only: no DUT login and no write to the line.
        self.attach_only = kwargs.pop("attach_only", False)
        # For telnet console, neither console username or password is needed
        # so we assign sonic_username/sonic_password to username/password
        kwargs['host'] = kwargs['console_host']
        kwargs['port'] = kwargs['console_port']
        # Don't set the value of password here because we will loop
        # among all passwords in __init__
        kwargs['username'] = kwargs['sonic_username']
        kwargs['console_username'] = kwargs['sonic_username']
        # An attach-only console does not log in, so it may have no password
        kwargs['console_password'] = kwargs['sonic_password'] or [None]
        kwargs['device_type'] = "_telnet"
        super(TelnetConsoleConn, self).__init__(**kwargs)

    def _try_session_preparation(self, force_data=True):
        # netmiko writes a RETURN before session preparation; an attach-only console must not.
        return super(TelnetConsoleConn, self)._try_session_preparation(force_data=force_data and not self.attach_only)

    def session_preparation(self):
        if not self.attach_only:
            super(TelnetConsoleConn, self).session_preparation()

    def cleanup(self):
        # netmiko's cleanup writes "exit" to the line; an attach-only console only closes.
        if not self.attach_only:
            super(TelnetConsoleConn, self).cleanup()

    def telnet_login(
        self,
        pri_prompt_terminator=DEFAULT_LOGIN_PRI_PROMPT_TERMINATOR,
        alt_prompt_terminator=DEFAULT_LOGIN_ALT_PROMPT_TERMINATOR,
        username_pattern=DEFAULT_LOGIN_USERNAME_PATTERN,
        pwd_pattern=DEFAULT_LOGIN_PWD_PATTERN,
        delay_factor=DEFAULT_DELAY_FACTOR,
        max_loops=DEFAULT_LOGIN_MAX_LOOPS,
    ):
        """Telnet login. Can be username/password or just password."""
        if self.attach_only:
            return ""
        delay_factor = self.select_delay_factor(delay_factor)
        time.sleep(RESPONSE_WAIT_S * delay_factor)

        output = ""
        return_msg = ""
        username_sent = False
        password_sent = False
        i = 1
        while i <= max_loops:
            try:
                output = self.read_channel()
                return_msg += output

                # Search for username pattern / send username
                if not username_sent and re.search(username_pattern, output, flags=re.I):
                    self.write_channel(self.username + self.TELNET_RETURN)
                    username_sent = True
                    time.sleep(RESPONSE_WAIT_S * delay_factor)
                    output = self.read_channel()
                    return_msg = output

                # Search for password pattern / send password
                if username_sent and not password_sent and re.search(pwd_pattern, output, flags=re.I):
                    self.write_channel(self.password + self.TELNET_RETURN)
                    time.sleep(READ_INTERVAL_S * delay_factor)
                    password_sent = True
                    output = self.read_channel()
                    return_msg += output
                    if re.search(
                        pri_prompt_terminator, output, flags=re.M
                    ) or re.search(alt_prompt_terminator, output, flags=re.M):
                        return return_msg

                # Support direct telnet through terminal server
                if re.search(r"initial configuration dialog\? \[yes/no\]: ", output):
                    self.write_channel("no" + self.TELNET_RETURN)
                    time.sleep(READ_INTERVAL_S * delay_factor)
                    count = 0
                    while count < CISCO_SETUP_DIALOG_MAX_READS:
                        output = self.read_channel()
                        return_msg += output
                        if re.search(r"ress RETURN to get started", output):
                            output = ""
                            break
                        time.sleep(CISCO_SETUP_DIALOG_WAIT_S * delay_factor)
                        count += 1

                # Check for device with no password configured
                if re.search(r"assword required, but none set", output):
                    self.remote_conn.close()
                    msg = "Login failed - Password required, but none set: {}".format(
                        self.host
                    )
                    raise NetMikoAuthenticationException(msg)

                # Check if proper data received
                if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
                    alt_prompt_terminator, return_msg, flags=re.M
                ):
                    return return_msg

                #  Check if login failed
                if re.search(LOGIN_FAILURE_PATTERN, output, flags=re.M):
                    self.remote_conn.close()
                    # Wait a short time or the next login will be refused
                    time.sleep(RESPONSE_WAIT_S * delay_factor)
                    msg = "Login failed: {} password: {}".format(self.host, self.password)
                    raise NetMikoAuthenticationException(msg)

                self.write_channel(self.TELNET_RETURN)
                time.sleep(READ_INTERVAL_S * delay_factor)
                i += 1
            except EOFError:
                self.remote_conn.close()
                msg = "Login failed: {}".format(self.host)
                raise NetMikoAuthenticationException(msg)

        # Last try to see if we already logged in
        self.write_channel(self.TELNET_RETURN)
        time.sleep(READ_INTERVAL_S * delay_factor)
        output = self.read_channel()
        return_msg += output
        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
            alt_prompt_terminator, output, flags=re.M
        ):
            return return_msg

        self.remote_conn.close()
        msg = "Login failed: {}".format(self.host)
        raise NetMikoAuthenticationException(msg)
