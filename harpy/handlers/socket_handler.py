# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling sockets."""

import socket
import harpy.data.core as core
from harpy.handlers.exception_handler import ExceptionHandler


class SocketHandler:
    """Handler of sockets."""

    @ExceptionHandler()
    def __init__(self, protocol):
        self.l2soc = socket.socket(
            socket.PF_PACKET, socket.SOCK_RAW, socket.htons(protocol)
        )

    def set_options(self):
        """Set socket options."""

        self.l2soc.setblocking(False)  # Non-blocking mode
        self.l2soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l2soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    @ExceptionHandler(core.SOCKET)
    def bind(self, interface, port):
        """
        Bind the socket to an interface.

        :param interface: Network interface to send/sniff packets.
        :param port: Port to bind to an interface.
        """

        self.l2soc.bind((interface, port))

    def close(self):
        """Close the socket."""

        self.l2soc.close()
