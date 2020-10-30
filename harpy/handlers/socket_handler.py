# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling sockets."""

import socket
import harpy.core.data as data
from harpy.handlers.exception_handler import ExceptionHandler


class SocketHandler:
    """Handler of sockets."""

    @ExceptionHandler(data.SOCKET)
    def __init__(self, protocol):
        self.raw_soc = socket.socket(
            socket.PF_PACKET, socket.SOCK_RAW, socket.htons(protocol)
        )

    def set_options(self):
        """Set socket options."""

        self.raw_soc.setblocking(False)  # Non-blocking mode
        self.raw_soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.raw_soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    @ExceptionHandler(data.SOCKET)
    def bind(self, interface, port):
        """
        Bind the socket to an interface.

        :param interface: Network device to send/sniff packets.
        :param port: Port to bind to an interface.
        """

        self.raw_soc.bind((interface, port))

    def close(self):
        """Close the socket."""

        self.raw_soc.close()
