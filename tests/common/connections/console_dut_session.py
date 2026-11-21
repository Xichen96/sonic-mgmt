"""Logged-in SONiC shell on a DUT serial console line.

ConsoleDutSession is the DUT layer of a console connection. It runs on top of a
line: a byte stream already attached to the DUT serial port (a console-server
SSH or telnet session, conserver, picocom, ...). The line is supplied by the
caller and needs only three methods:

    read() -> str       return the text available now, "" if none; never blocks
    write(data: str)    send text to the DUT
    close()             close the transport

Timeouts: login() takes the connect timeout and every later call takes its own.
Each call returns its result within that time, or None, runs entirely in the
caller's thread, and does nothing more once it has returned. Nothing is retried:
a failed login returns None and leaves the line to the caller.

The session never writes on its own initiative while the line shows bootloader
output: any key, even a bare CR, aborts autoboot and traps the DUT in the
bootloader. Writes the caller asks for (send_command, write) are sent as given.
"""
import logging
import re
import time

logger = logging.getLogger(__name__)

RETURN = "\n"

# Bootloader / autoboot output (Arista Aboot, GRUB, U-Boot, ONIE, kernel load).
# The tokens are specific so ordinary SONiC shell output does not match: no bare
# "Aboot" (image names like sonic-aboot-broadcom.swi), no bare "autoboot", and the
# boot-in-progress verbs are line-anchored.
BOOTLOADER_BANNER_RE = re.compile(
    r"Press\s+Control[-\s]?C\s+now|"
    r"Aboot#|"
    r"GNU\s+GRUB|grub\s*>|grub\s+rescue\s*>|"
    r"Hit\s+any\s+key\s+to\s+stop\s+autoboot|"
    r"autoboot\s+in\b|stop\s+autoboot|"
    r"ONIE:|"
    r"^\s*Booting\b|"
    r"^\s*Loading\s+(?:Linux|initrd|initial\s+ramdisk|kernel|vmlinuz)",
    flags=re.I | re.M,
)

# Prompts only count at the very end of the output, where the DUT waits for input.
LOGIN_PROMPT_RE = re.compile(r"(?<!Last )login:\s*$", flags=re.I)
PASSWORD_PROMPT_RE = re.compile(r"[Pp]assword:\s*$")
SHELL_PROMPT_RE = re.compile(r"\S+@\S+:[^\n]*[$#]\s*$")
ANY_PROMPT_RE = re.compile(
    r"(?:{})|(?:{})".format(SHELL_PROMPT_RE.pattern, LOGIN_PROMPT_RE.pattern), flags=re.I)

POLL_INTERVAL_S = 0.1
# A silent line is nudged with a CR only after it has been quiet this long. An
# autoboot window repaints its countdown, so a line this quiet is not in one.
QUIET_BEFORE_NUDGE_S = 2.0
# Only the latest output is classified. Bootloader output older than this has
# scrolled past, so the DUT has moved on to booting Linux.
LOOKBACK_CHARS = 4096


class ConsoleDutSession(object):
    """A logged-in SONiC shell on a console line. Create it with login()."""

    def __init__(self, line):
        self._line = line
        self._pending = ""
        self._closed = False

    @classmethod
    def login(cls, line, username, passwords, timeout):
        """Log in to the SONiC shell on ``line`` within ``timeout`` seconds.

        Tries each password in ``passwords`` in order. Returns the session, or
        None if the shell was not reached in time or every password failed. On
        None the line stays open and belongs to the caller.
        """
        session = cls(line)
        try:
            if session._login(username, passwords, time.monotonic() + timeout):
                return session
        except Exception as e:
            logger.warning("Console login failed: %s", e)
        return None

    def send_command(self, command, timeout, expect=None):
        """Run ``command`` and return its output within ``timeout`` seconds, else None.

        The output is the text between the command echo and ``expect`` (a regex,
        by default the shell prompt).
        """
        if self._closed:
            return None
        pattern = re.compile(expect) if expect else SHELL_PROMPT_RE
        try:
            self._pending = ""
            self._line.read()
            self._line.write(command + RETURN)
            found = self._read_until(pattern, time.monotonic() + timeout)
        except Exception as e:
            logger.warning("Console command %r failed: %s", command, e)
            return None
        if found is None:
            return None
        text, match_start = found
        output = re.sub(r"\r+\n", "\n", text[:match_start])
        return output.partition("\n")[2].strip("\n")

    def write(self, data):
        """Send ``data`` as is. Returns False, sending nothing, once disconnected."""
        if self._closed:
            return False
        try:
            self._line.write(data)
        except Exception as e:
            logger.warning("Console write failed: %s", e)
            return False
        return True

    def read_until(self, pattern, timeout):
        """Return the output up to and including ``pattern`` within ``timeout`` seconds, else None.

        Output after the match is kept for the next call.
        """
        if self._closed:
            return None
        try:
            found = self._read_until(re.compile(pattern), time.monotonic() + timeout)
        except Exception as e:
            logger.warning("Console read failed: %s", e)
            return None
        return None if found is None else found[0]

    def disconnect(self, timeout=None):
        """Close the session. Nothing is sent or read afterwards.

        With ``timeout`` None the line is closed abruptly, without writing. With a
        timeout the shell is logged out first, waiting up to ``timeout`` seconds
        for the login prompt; that is skipped if the line shows bootloader output.
        """
        if self._closed:
            return
        self._closed = True
        try:
            if timeout is not None:
                self._logout(time.monotonic() + timeout)
        except Exception as e:
            logger.warning("Console logout failed: %s", e)
        finally:
            self._line.close()

    def _login(self, username, passwords, deadline):
        index = 0
        user_sent = password_sent = False
        output = ""
        last_activity = time.monotonic()
        while time.monotonic() < deadline:
            data = self._line.read()
            if data:
                output = (output + data)[-LOOKBACK_CHARS:]
                last_activity = time.monotonic()
            reply = None
            if SHELL_PROMPT_RE.search(output):
                if password_sent:
                    return True
                logger.info("Console is at a shell left from an earlier session; logging it out")
                reply = "exit" + RETURN
                user_sent = False
            elif LOGIN_PROMPT_RE.search(output):
                if password_sent:
                    index += 1
                    password_sent = False
                    if index == len(passwords):
                        logger.warning("Console login rejected every password")
                        return False
                reply = username + RETURN
                user_sent = True
            elif PASSWORD_PROMPT_RE.search(output):
                if user_sent and not password_sent:
                    reply = passwords[index] + RETURN
                    password_sent = True
                else:
                    # Prompt left from someone else's login, or asked again: an empty
                    # answer fails it and brings the login prompt back.
                    reply = RETURN
            elif BOOTLOADER_BANNER_RE.search(output):
                pass
            elif not user_sent and time.monotonic() - last_activity >= QUIET_BEFORE_NUDGE_S:
                reply = RETURN
            if reply is not None:
                self._line.write(reply)
                output = ""
                last_activity = time.monotonic()
            time.sleep(POLL_INTERVAL_S)
        logger.warning("Console login did not finish in time")
        return False

    def _logout(self, deadline):
        self._pending += self._line.read()
        if BOOTLOADER_BANNER_RE.search(self._pending[-LOOKBACK_CHARS:]):
            logger.warning("Console shows bootloader output; closing without logging out")
            return
        self._pending = ""
        self._line.write(RETURN)
        found = self._read_until(ANY_PROMPT_RE, deadline)
        if found is None or not SHELL_PROMPT_RE.search(found[0]):
            return
        self._line.write("exit" + RETURN)
        if self._read_until(LOGIN_PROMPT_RE, deadline) is None:
            logger.warning("Console did not return to the login prompt after exit")

    def _read_until(self, pattern, deadline):
        """Return (text up to the end of the match, match start), or None at the deadline."""
        while True:
            self._pending += self._line.read()
            match = pattern.search(self._pending)
            if match:
                text = self._pending[:match.end()]
                self._pending = self._pending[match.end():]
                return text, match.start()
            if time.monotonic() >= deadline:
                return None
            time.sleep(POLL_INTERVAL_S)
