FROM target/consensource-rust:stable

COPY . /processor
WORKDIR processor
RUN cargo build

ENV PATH=$PATH:/processor/target/debug/