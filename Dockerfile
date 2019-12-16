FROM target/consensource:rust-base-1.38

COPY . /processor
WORKDIR processor
RUN cargo build

ENV PATH=$PATH:/processor/target/debug/