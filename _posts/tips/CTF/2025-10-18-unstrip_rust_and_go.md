---
title: "Unstrip Rust and Go binray with Cerberus"
date: 2025-10-18 17:30:00 +0900
categories: [TIPS, REV]
tags: [ctf, tips, rev, reversing, unstrip, rust]
---

# Cerberus 사용해서 Strip된 Rust 또는 Go binary분석하기

ref: https://frereit.de/hackday_rusty_rev/

엄청 큰 차이는 없는데 그래도 메모해두면 언젠가 또 쓸 일 있을거같아서 저장.

```
# git clone --recursive https://github.com/h311d1n3r/Cerberus && cd Cerberus
# docker build -f ./docker/ubuntu/Dockerfile-22.04 -t cerberus .
# cd ..
# docker run --rm -it -v "$(pwd):/mnt/data" cerberus:latest /bin/bash
root@cd00b99d9341:/mnt/data# apt install curl
root@cd00b99d9341:/mnt/data# curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
root@cd00b99d9341:/mnt/data# . "$HOME/.cargo/env" 
root@cd00b99d9341:/mnt/data# /root/Cerberus/build/cerberus inner.elf -output inner_resym.elf
---------- Cerberus (v2.0) ----------
[*] Identified package manager: apt
[*] Running as root.
[*] Identified file as UNIX - Executable and Linkable Format (ELF).
[*] Identified language : Rust
[*] Continue analysis with this language ? (Y/n) 
[*] Using Rust for analysis.
[*] The following packages are required :
With apt:
- git
- golang
- python3
- python3-pip
- patch
With pip3:
- pyinstaller
With git:
- radare2
- Goliath
With cargo:
- cross
[*] Proceed to installation ? (Y/n) 
[...]
[*] File was found to be stripped.
[*] Extracting libraries...
[+] Identified 2 libraries.
[*] Here is the current list of libraries :
-------------------------------
1. rand:0.8.5
2. rand_chacha:0.3.1
-------------------------------
1. Validate 2. Add library 3. Change library version 4. Remove library
[*] Your choice ? (1-4) 1
[*] Installing libraries...
[*] Installing rand:0.8.5...
[+] Success !
[*] Installing rand_chacha:0.3.1...
[+] Success !
[+] Installed 2 libraries.
[*] Analyzing target functions...
[+] Analyzed 528 functions.
[*] Matching with functions from libraries...
[+] Matched 324 functions. Matching rate: 61%
[*] Demangling function names...
[+] Done !
[*] Writing output file...
[+] Done !
root@cd00b99d9341:/mnt/data# exit
```