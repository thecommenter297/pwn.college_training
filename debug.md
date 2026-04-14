## Giới thiệu file template debug.py dùng để debug

**debug.py**
```python
from pwn import *
p = gdb.debug('./shellcode-elf', gdbscript='''
              source /opt/pwndbg/gdbinit.py
                b *_start
                b *loop_4096
                b *loop_4096+9
              ''')


p.interactive()
```
