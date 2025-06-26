FROM kathara/base
LABEL org.opencontainers.image.authors="Kathara Team <contact@kathara.org>"

ARG DEBIAN_FRONTEND="noninteractive"

RUN apt update -y && apt upgrade -y
RUN apt install -y clang llvm libelf-dev gcc make build-essential git iproute2
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git && cd bpftool/src && make && make install
RUN apt install -y bpfcc-tools linux-headers-$(debian)
RUN apt install python3-bpfcc
RUN apt install -y libbpf-dev
RUN apt install -y bpftrace
RUN apt clean && rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*
RUN apt-get update && apt-get install -y libelf-dev zlib1g-dev wget pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp
RUN FILE_NAME=$(wget -q -O - https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/ | \
    tac | \
    grep -m 1 -o "iproute2-6[\.0-9]*[0-9]" | \
    head -n 1) && \
    wget -q https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/$FILE_NAME.tar.xz && \
    tar xf $FILE_NAME.tar.xz && \
    cd $FILE_NAME && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf $FILE_NAME* && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
WORKDIR /