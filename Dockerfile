# -------------=== processor build ===-------------
FROM ubuntu:xenial as processor-rust-builder

ENV VERSION=0.1.0

RUN apt-get update \
 && apt-get install -y \
 curl \
 gcc \
 git \
 libssl-dev \
 libzmq3-dev \
 pkg-config \
 python3 \
 unzip

# For Building Protobufs
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y \
 && curl -OLsS https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip \
 && unzip protoc-3.5.1-linux-x86_64.zip -d protoc3 \
 && rm protoc-3.5.1-linux-x86_64.zip

ENV PATH=$PATH:/protoc3/bin
RUN /root/.cargo/bin/cargo install cargo-deb

COPY . /project

WORKDIR /project/

RUN /root/.cargo/bin/cargo deb --deb-version $VERSION

# -------------=== processor rust docker build ===-------------
FROM ubuntu:xenial

COPY --from=processor-rust-builder /project/target/debian/consensource-processor*.deb /tmp

RUN apt-get update \
 && dpkg -i /tmp/consensource-processor*.deb || true \
 && apt-get -f -y install