# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Module for handling sockets."""

import socket
import harpy.core.data as data


class SocketHandler:
    """Handler of sockets."""

    def __init__(self, protocol):
        try:
            self.raw_soc = socket.socket(
                socket.PF_PACKET, socket.SOCK_RAW, socket.htons(protocol)
            )
        except OSError as err:
            if data.oserror_handler(err=err, who=data.ERR_SOCKET) is None:
                raise

    def set_options(self):
        """Set socket options."""

        self.raw_soc.setblocking(True)  # Prevent BlockingIOError
        self.raw_soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.raw_soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    def bind(self, interface, port):
        """
        Bind a socket to an interface.

        :param interface: Network device to send/sniff packets.
        :param port: Port to bind to an interface.
        """

        try:
            self.raw_soc.bind((interface, port))
        except OSError as err:
            if data.oserror_handler(err=err, who=data.ERR_SOCKET) is None:
                raise

    def close(self):
        """Close a socket."""

        self.raw_soc.close()
