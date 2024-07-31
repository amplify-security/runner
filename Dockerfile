FROM rust:1.80.0-alpine3.20 as builder

WORKDIR /usr/src/app

RUN apk add --no-cache musl-dev

COPY Cargo.toml Cargo.lock ./
COPY src ./src/
RUN cargo build --release --locked
RUN strip ./target/release/amplify-runner

FROM alpine:3.20.2

RUN apk add --no-cache git

COPY --from=builder /usr/src/app/target/release/amplify-runner /usr/bin/amplify-runner

ENTRYPOINT ["/usr/bin/amplify-runner"]
