# This file is part of hARPy

import sys
import socket


class SocketHandler:
    def __init__(self, protocol):
        try:
            self.raw_socket = socket.socket(
                socket.PF_PACKET, socket.SOCK_RAW, socket.htons(protocol)
            )
        except OSError as err:
            if err.errno == 1:  # 1: Operation not permitted
                sys.exit("socket: error: operation not permitted")

    def set_options(self):
        self.raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    def bind(self, interface, port):
        try:
            self.raw_socket.bind((interface, port))
        except OSError as err:
            if err.errno == 19:  # 19: No such device
                sys.exit(f"socket: error: no such device to bind, {interface}")
