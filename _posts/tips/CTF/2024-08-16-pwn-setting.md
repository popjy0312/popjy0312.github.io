---
title: "[docker hub] docker + vscode 환경에서의 pwnable 환경 세팅"
date: 2099-08-16 14:30:00 +0900
categories: [TIPS, PWN]
tags: [ctf, pwn, docker, tips, tools]
---

# [docker hub] docker + vscode 환경에서의 pwnable 환경 세팅

`pwnable` 문제는 특히나 환경을 타는 경우가 많기 때문에 `Dockerfile`이 주어지는 경우가 많다.

예를 들어서, Heap문제를 풀려는데, 하위 버전의 GLIBC에서 동작하는 방식을 유도하기 위해서 낮은 버전의 Ubuntu에서 돌아가는 `Dockerfile`을 제공하는 식이다.

local에서 디버깅할 때, docker에 돌아가는 process를 docker top을 활용해서 디버깅하려고 했더니, 심볼이나 라이브러리 로딩 관련한 여러가지 문제가 발생했다.

그 이유는 gdb도 여러가지 기능을 수행하는데 library가 필요하기 때문이다.

이런 문제를 해결하는 방법은 크게 아래의 2가지 방법이 있다.
1. library들이 포함된 sysroot를 인자로 주는 방법
2. gdb를 도커 컨테이너 내부에서 돌리는 방법

이 중에서 좀 더 일반적으로 사용가능하고 다른 이슈가 적게 발생할 것으로 생각되는 2번 방법으로 환경을 구축하는 방법을 작성하고자 한다.

## 1. pwnable tool들이 세팅된 base image 생성
docker hub에 14.04, 16.04, 18.04, 20.04, 22.04 총 5가지의 Ubuntu version에 대한 base image를 생성했다.

추후 문제를 풀 때에는 docker hub에 올려둔 base image를 활용해서 도커 환경을 구축한다.

### 1.1. base image 생성


base image는 다음과 같은 도구들을 설치했다.

- python3
- pwntools
- tmux
- gef

도커 hub에 로그인
```shell
docker login
```

Dockerfile:
```
# Ubuntu 14.04
FROM ubuntu:14.04 as pwnable-base-14.04

RUN apt-get update && apt-get install -y \
    gdb \
    python3 \
    python3-pip \
    tmux \
    vim \
    wget \
    netcat \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install pwntools

RUN wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py \
    && echo source ~/.gdbinit-gef.py >> ~/.gdbinit

ENV TERM=xterm

WORKDIR /pwn

CMD ["/bin/bash"]

# Ubuntu 16.04
FROM ubuntu:16.04 as pwnable-base-16.04

RUN apt-get update && apt-get install -y \
    gdb \
    python3 \
    python3-pip \
    tmux \
    vim \
    wget \
    netcat \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install pwntools

RUN wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py \
    && echo source ~/.gdbinit-gef.py >> ~/.gdbinit

ENV TERM=xterm

WORKDIR /pwn

CMD ["/bin/bash"]

# Ubuntu 18.04
FROM ubuntu:18.04 as pwnable-base-18.04

RUN apt-get update && apt-get install -y \
    gdb \
    python3 \
    python3-pip \
    tmux \
    vim \
    wget \
    netcat \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install pwntools

RUN wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py \
    && echo source ~/.gdbinit-gef.py >> ~/.gdbinit

ENV TERM=xterm

WORKDIR /pwn

CMD ["/bin/bash"]

# Ubuntu 20.04
FROM ubuntu:20.04 as pwnable-base-20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gdb \
    python3 \
    python3-pip \
    tmux \
    vim \
    wget \
    netcat \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install pwntools

RUN wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py \
    && echo source ~/.gdbinit-gef.py >> ~/.gdbinit

ENV TERM=xterm

WORKDIR /pwn

CMD ["/bin/bash"]

# Ubuntu 22.04
FROM ubuntu:22.04 as pwnable-base-22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gdb \
    python3 \
    python3-pip \
    tmux \
    vim \
    wget \
    netcat \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install pwntools

RUN wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py \
    && echo source ~/.gdbinit-gef.py >> ~/.gdbinit

ENV TERM=xterm

WORKDIR /pwn

CMD ["/bin/bash"]
```

build.sh:
```shell
#!/bin/bash

DOCKER_HUB_USERNAME="popjy0312"

UBUNTU_VERSIONS=("14.04" "16.04" "18.04" "20.04" "22.04")

for version in "${UBUNTU_VERSIONS[@]}"
do
    echo "Building pwnable-base:$version"
    docker build --target pwnable-base-$version -t $DOCKER_HUB_USERNAME/pwnable-base:$version .

    echo "Pushing pwnable-base:$version to Docker Hub"
    docker push $DOCKER_HUB_USERNAME/pwnable-base:$version
done

echo "All images have been built and pushed successfully!"
```

이후 Dockerfile에서 이미지 가져올때 아래와같이 가져오면 된다.
```
FROM popjy0312/pwnable-base:16.04
```

## 2. Docker 실행 관련 설정

exploit 코드는 vscode의 편집기로 작성하고싶은데, gdb는 도커 컨테이너 내부에서 실행돼야한다.
따라서 -v 옵션으로 volume을 연결하여 도커 컨테이너에 exploit코드가 저장되도록 한다.

```sh
PROJ_NAME ?= simple_memo
PORT ?= 8215
DOCKER_FLAGS ?= --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --privileged  
PWD := $(shell pwd)
EXDIR := $(PWD)/../ex/

all: build

build:
        docker build -t $(PROJ_NAME) .

up:
        docker run -d -p $(PORT):$(PORT) -v $(EXDIR):/pwn \
                $(DOCKER_FLAGS) \
                --name $(PROJ_NAME) $(PROJ_NAME)

down:
        docker rm -f $(PROJ_NAME)

clean:
        docker rmi -f $(PROJ_NAME)

shell:
        docker exec -it $(PROJ_NAME) /bin/bash

rootshell:
        docker exec --user root -it $(PROJ_NAME) /bin/bash
```