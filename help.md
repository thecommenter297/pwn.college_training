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

## Help

**Kết nối đến pwn.college bằng `ssh`**
```shell
ssh -i key hacker@dojo.pwn.college
```

**Cách tải file từ pwn.college về máy**
> Dùng lệnh này khi đã ssh đến server
```shell
scp -i <đường dẫn đến file key> hacker@dojo.pwn.college:<link_file> .
```
#### Giải nén:
```shell
unzip file.zip
```

##### Patch file libcapstone.so.5 và libc trên pwn.college
```bash
patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./ello-ackers

patchelf --set-rpath '$ORIGIN' ./ello-ackers
```

**Cài môi trường mà challenge yêu cầu (ví dụ docker)**
<details>
<summary>Setup và chạy docker</summary>
    
```shell
$ sudo apt install docker.io #nếu bạn chưa cài docker
$ sudo docker build -t <tên_challenge> .
$ sudo docker run -p 1337:1337 <tên_challenge> #port này các bạn xem trong file docker nhé
```
</details>

