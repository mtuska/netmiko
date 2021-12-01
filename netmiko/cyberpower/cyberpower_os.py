"""CyberPower OS SSH Driver for Netmiko"""
from typing import Any
from os import path
import re
import time
from socket import socket

from telnetlib import DO, DONT, ECHO, IAC, WILL, WONT, Telnet

from netmiko.cisco_base_connection import CiscoSSHConnection
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

class CyberPowerOSBase(CiscoSSHConnection):
    """Common methods for CyberPower OS, both SSH and Telnet."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        default_enter = kwargs.get("default_enter")
        kwargs["default_enter"] = "\r" if default_enter is None else default_enter
        super().__init__(*args, **kwargs)

    def session_preparation(self) -> Any:
        """Prepare the session after the connection has been established."""
        self.ansi_escape_codes = True
        # self._test_channel_read(pattern=r"[>#]")
        self.set_base_prompt()
    
    def special_login_handler(self, delay_factor: float = 1.0) -> None:
        """
        CyberPower OS presents with the following on login:

        Login Name:
        Login Password: ****
        """
        new_data = ""
        time.sleep(0.1)
        start = time.time()
        login_timeout = 20
        while time.time() - start < login_timeout:
            output = self.read_channel() if not new_data else new_data
            new_data = ""
            if output:
                if "Login Name:" in output:
                    assert isinstance(self.username, str)
                    self.write_channel(self.username + self.RETURN)
                elif "Login Password:" in output:
                    assert isinstance(self.password, str)
                    self.write_channel(self.password + self.RETURN)
                    break
                time.sleep(0.1)
            else:
                # No new data...sleep longer
                time.sleep(0.5)
                new_data = self.read_channel()
                # If still no data, send an <enter>
                if not new_data:
                    self.write_channel(self.RETURN)
        else:  # no-break
            msg = """
Login process failed to CyberPower OS device. Unable to login in {login_timeout} seconds.
"""
            raise NetmikoTimeoutException(msg)

class CyberPowerOSSSH(CyberPowerOSBase):
    """CyberPower OS SSH Driver.

    To make it work, we have to override the SSHClient _auth method and manually handle
    the username/password.
    """

    pass


class CyberPowerOSTelnet(CyberPowerOSBase):
    """CyberPower OS Telnet Driver."""

    def _process_option(self, tsocket: socket, command: bytes, option: bytes) -> None:
        """
        CyberPower OS does not always echo commands to output by default.
        If server expresses interest in 'ECHO' option, then reply back with 'DO
        ECHO'
        """
        if option == ECHO:
            tsocket.sendall(IAC + DO + ECHO)
        elif command in (DO, DONT):
            tsocket.sendall(IAC + WONT + option)
        elif command in (WILL, WONT):
            tsocket.sendall(IAC + DONT + option)

    def command_echo_read(self, cmd: str, read_timeout: float) -> str:

        # Make sure you read until you detect the command echo (avoid getting out of sync)
        new_data = self.read_channel()

        # There can be echoed prompts that haven't been cleared before the cmd echo
        # this can later mess up the trailing prompt pattern detection. Clear this out.
        search_pattern = self._prompt_handler(True)
        lines = new_data.split(search_pattern)
        if len(lines) == 2:
            # lines[-1] should realistically just be the null string
            new_data = f"{cmd}{lines[-1]}"
        else:
            # cmd exists in the output multiple times? Just retain the original output
            pass
        return new_data

    def telnet_login(self, *args: Any, **kwargs: Any) -> str:
        # set callback function to handle telnet options.
        assert isinstance(self.remote_conn, Telnet)
        self.remote_conn.set_option_negotiation_callback(self._process_option)
        return self._telnet_login(*args, **kwargs)

    def _telnet_login(
        self,
        pri_prompt_terminator: str = r"\#\s*$",
        alt_prompt_terminator: str = r">\s*$",
        username_pattern: str = r"Login Name",
        pwd_pattern: str = r"Login Password",
        delay_factor: float = 1.0,
        max_loops: int = 20,
    ) -> str:
        """Telnet login. Can be username/password or just password."""
        delay_factor = self.select_delay_factor(delay_factor)

        if delay_factor < 1:
            if not self._legacy_mode and self.fast_cli:
                delay_factor = 1

        # Double initial time
        time.sleep(2 * delay_factor)

        output = ""
        return_msg = ""
        outer_loops = 3
        inner_loops = int(max_loops / outer_loops)
        i = 1
        for _ in range(outer_loops):
            while i <= inner_loops:
                try:
                    output = self.read_channel()
                    return_msg += output

                    # Search for username pattern / send username
                    if re.search(username_pattern, output, flags=re.I):
                        # Sometimes username/password must be terminated with "\r" and not "\r\n"
                        self.write_channel(self.username + "\r")
                        time.sleep(1 * delay_factor)
                        output = self.read_channel()
                        return_msg += output

                    # Search for password pattern / send password
                    if re.search(pwd_pattern, output, flags=re.I):
                        # Sometimes username/password must be terminated with "\r" and not "\r\n"
                        assert isinstance(self.password, str)
                        self.write_channel(self.password + "\r")
                        # Takes extra time from login to get console
                        time.sleep(3 * delay_factor)
                        output = self.read_channel()
                        return_msg += output

                    # Check if proper data received
                    if re.search(
                        pri_prompt_terminator, output, flags=re.M
                    ) or re.search(alt_prompt_terminator, output, flags=re.M):
                        return return_msg

                    i += 1

                except EOFError:
                    assert self.remote_conn is not None
                    self.remote_conn.close()
                    msg = f"Login failed: {self.host}"
                    raise NetmikoAuthenticationException(msg)

            # Try sending an <enter> to restart the login process
            # self.write_channel(self.TELNET_RETURN)
            time.sleep(1 * delay_factor)
            i = 1

        # Last try to see if we already logged in
        self.write_channel(self.TELNET_RETURN)
        time.sleep(0.5 * delay_factor)
        output = self.read_channel()
        return_msg += output
        if re.search(pri_prompt_terminator, output, flags=re.M) or re.search(
            alt_prompt_terminator, output, flags=re.M
        ):
            return return_msg

        assert self.remote_conn is not None
        self.remote_conn.close()
        msg = f"Login failed: {self.host}"
        raise NetmikoAuthenticationException(msg)