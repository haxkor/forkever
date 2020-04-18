"""
Error pipe and serialization code comes from Python 2.5 subprocess module.
"""
from os import (
    fork, execvp, execvpe, waitpid,
    close, dup2, pipe,
    read, write, devnull, sysconf)
from sys import exc_info
from traceback import format_exception
from ptrace.os_tools import RUNNING_WINDOWS
from ptrace.binding import ptrace_traceme
from ptrace import PtraceError
from sys import exit
from errno import EINTR
import fcntl
import pickle

try:
    MAXFD = sysconf("SC_OPEN_MAX")
except Exception:
    MAXFD = 256


class ChildError(RuntimeError):
    pass


class ChildPtraceError(ChildError):
    pass


def _set_cloexec_flag(fd):
    if RUNNING_WINDOWS:
        return
    try:
        cloexec_flag = fcntl.FD_CLOEXEC
    except AttributeError:
        cloexec_flag = 1

    old = fcntl.fcntl(fd, fcntl.F_GETFD)
    fcntl.fcntl(fd, fcntl.F_SETFD, old | cloexec_flag)


def _waitpid_no_intr(pid, options):
    """Like os.waitpid, but retries on EINTR"""
    while True:
        try:
            return waitpid(pid, options)
        except OSError as e:
            if e.errno == EINTR:
                continue
            else:
                raise


def _read_no_intr(fd, buffersize):
    """Like os.read, but retries on EINTR"""
    while True:
        try:
            return read(fd, buffersize)
        except OSError as e:
            if e.errno == EINTR:
                continue
            else:
                raise


def _write_no_intr(fd, s):
    """Like os.write, but retries on EINTR"""
    while True:
        try:
            return write(fd, s)
        except OSError as e:
            if e.errno == EINTR:
                continue
            else:
                raise


def _createParent(pid, errpipe_read):
    # Wait for exec to fail or succeed; possibly raising exception
    data = _read_no_intr(errpipe_read, 1048576)  # Exceptions limited to 1 MB
    close(errpipe_read)
    if data:
        _waitpid_no_intr(pid, 0)
        child_exception = pickle.loads(data)
        raise child_exception


def _createChild(arguments, no_stdout, env, errpipe_write):
    # Child code
    try:
        ptrace_traceme()
    except PtraceError as err:
        raise ChildError(str(err))

    # Close all files except 0, 1, 2 and errpipe_write
    for fd in range(3, MAXFD):
        if fd == errpipe_write:
            continue
        try:
            close(fd)
        except OSError:
            pass
    try:
        _execChild(arguments, no_stdout, env)
    except:   # noqa: E722
        exc_type, exc_value, tb = exc_info()
        # Save the traceback and attach it to the exception object
        exc_lines = format_exception(exc_type, exc_value, tb)
        exc_value.child_traceback = ''.join(exc_lines)
        _write_no_intr(errpipe_write, pickle.dumps(exc_value))
    exit(255)


def _execChild(arguments, no_stdout, env):
    if no_stdout:
        try:
            null = open(devnull, 'wb')
            dup2(null.fileno(), 1)
            dup2(1, 2)
            null.close()
        except IOError:
            close(2)
            close(1)
    try:
        if env is not None:
            execvpe(arguments[0], arguments, env)
        else:
            execvp(arguments[0], arguments)
    except Exception as err:
        raise ChildError(str(err))


def createChild(arguments, no_stdout, env=None):
    """
    Create a child process:
     - arguments: list of string where (e.g. ['ls', '-la'])
     - no_stdout: if True, use null device for stdout/stderr
     - env: environment variables dictionary

    Use:
     - env={} to start with an empty environment
     - env=None (default) to copy the environment
    """
    errpipe_read, errpipe_write = pipe()
    _set_cloexec_flag(errpipe_write)

    # Fork process
    pid = fork()
    if pid:
        close(errpipe_write)
        _createParent(pid, errpipe_read)
        return pid
    else:
        close(errpipe_read)
        _createChild(arguments, no_stdout, env, errpipe_write)
