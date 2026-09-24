#!/usr/bin/env python3
"""socket_activate.py <socket-path> <program> [args...]

Listen on a SOCK_SEQPACKET socket, accept one connection and exec <program>
with it, the way systemd starts a socket unit with Accept=yes: the connection
is fd 3, LISTEN_FDS=1 and LISTEN_PID is the pid that runs <program>.

Prints "listening" once a connect() can succeed.
"""

import os
import socket
import sys

SD_LISTEN_FDS_START = 3


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    path = sys.argv[1]
    program = sys.argv[2:]

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listener.bind(path)
    listener.listen(1)
    print('listening', flush=True)

    conn, _ = listener.accept()
    listener.close()

    # conn itself is close-on-exec and goes away with the exec
    os.dup2(conn.fileno(), SD_LISTEN_FDS_START)
    os.set_inheritable(SD_LISTEN_FDS_START, True)
    os.environ['LISTEN_FDS'] = '1'
    # exec keeps the pid
    os.environ['LISTEN_PID'] = str(os.getpid())
    os.execv(program[0], program)


if __name__ == '__main__':
    main()
