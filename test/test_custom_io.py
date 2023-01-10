#!/usr/bin/env python3

if __name__ == '__main__':
    import sys

    import pytest
    sys.exit(pytest.main([__file__] + sys.argv[1:]))

import os
import socket
import struct
import subprocess
import sys
import time
from os.path import join as pjoin

import pytest

from util import base_cmdline, basename

FUSE_OP_INIT = 26

FUSE_MAJOR_VERSION = 7
FUSE_MINOR_VERSION = 38

fuse_in_header_fmt = '<IIQQIIII'
fuse_out_header_fmt = '<IiQ'

fuse_init_in_fmt = '<IIIII44x'
fuse_init_out_fmt = '<IIIIHHIIHHI28x'


def sock_recvall(sock: socket.socket, bufsize: int) -> bytes:
    buf = bytes()
    while len(buf) < bufsize:
        buf += sock.recv(bufsize - len(buf))
    return buf


def tst_init(sock: socket.socket):
    unique_req = 10
    dummy_init_req_header = struct.pack(
        fuse_in_header_fmt, struct.calcsize(fuse_in_header_fmt) +
        struct.calcsize(fuse_init_in_fmt), FUSE_OP_INIT, unique_req, 0, 0, 0,
        0, 0)
    dummy_init_req_payload = struct.pack(
        fuse_init_in_fmt, FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION, 0, 0, 0)
    dummy_init_req = dummy_init_req_header + dummy_init_req_payload

    sock.sendall(dummy_init_req)

    response_header = sock_recvall(sock, struct.calcsize(fuse_out_header_fmt))
    packet_len, _, unique_res = struct.unpack(
        fuse_out_header_fmt, response_header)
    assert unique_res == unique_req

    response_payload = sock_recvall(sock, packet_len - len(response_header))
    response_payload = struct.unpack(fuse_init_out_fmt, response_payload)
    assert response_payload[0] == FUSE_MAJOR_VERSION


def test_hello_uds(output_checker):
    cmdline = base_cmdline + [pjoin(basename, 'example', 'hello_ll_uds')]
    print(cmdline)
    uds_process = subprocess.Popen(cmdline, stdout=output_checker.fd,
                                   stderr=output_checker.fd)
    time.sleep(1)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(1)
    sock.connect("/tmp/libfuse-hello-ll.sock")

    tst_init(sock)

    sock.close()
    uds_process.terminate()
    try:
        uds_process.wait(1)
    except subprocess.TimeoutExpired:
        uds_process.kill()
    os.remove("/tmp/libfuse-hello-ll.sock")
