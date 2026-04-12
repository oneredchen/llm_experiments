"""Command execution service with timeout management."""

import logging
import os
import subprocess
import threading
import traceback
from typing import Any, Dict, Union

logger = logging.getLogger(__name__)

COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", 180))


class CommandExecutor:
    """Class to handle command execution with better timeout management."""

    def __init__(self, command: Union[str, list], timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        # Determine if we should use shell mode based on command type
        self.use_shell = isinstance(command, str)
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False

    def _read_stdout(self):
        """Thread function to continuously read stdout."""
        for line in iter(self.process.stdout.readline, ""):
            self.stdout_data += line

    def _read_stderr(self):
        """Thread function to continuously read stderr."""
        for line in iter(self.process.stderr.readline, ""):
            self.stderr_data += line

    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully."""
        logger.info(f"Executing command: {self.command}")

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=self.use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
            )

            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()

            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(
                    f"Command timed out after {self.timeout} seconds. Terminating process."
                )

                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()

                # Update final output
                self.return_code = -1

            # Always consider it a success if we have output, even with timeout
            success = (
                True
                if self.timed_out and (self.stdout_data or self.stderr_data)
                else (self.return_code == 0)
            )

            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out
                and bool(self.stdout_data or self.stderr_data),
            }

        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data),
            }


def execute_command(command: Union[str, list], timeout: int = None) -> Dict[str, Any]:
    """
    Execute a command and return the result.

    Args:
        command: The command to execute (list for safe mode, string for shell mode)
        timeout: Optional custom timeout in seconds (falls back to default if None)

    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    executor = CommandExecutor(command, timeout=timeout or COMMAND_TIMEOUT)
    return executor.execute()
