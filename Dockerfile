FROM rust:1.84.0-alpine3.21 AS builder

WORKDIR /usr/src/app

RUN apk add --no-cache musl-dev

COPY Cargo.toml Cargo.lock ./
# Build trick to cache dependencies in a separate layer before building the whole project
RUN echo "fn main() {}" > dummy.rs && sed -i 's#src/main.rs#dummy.rs#' Cargo.toml
RUN cargo build --release
RUN sed -i 's#dummy.rs#src/main.rs#' Cargo.toml && rm dummy.rs
# End of build trick
COPY src ./src/
RUN cargo build --release --locked
RUN strip ./target/release/amplify-runner

FROM alpine:3.21.2

RUN apk add --no-cache git

COPY --from=builder /usr/src/app/target/release/amplify-runner /usr/bin/amplify-runner
# Runner needs to be able to write a ruleset in /, so this creates a writeable file in advance.
RUN touch /ruleset.json && chmod 777 /ruleset.json

CMD ["/usr/bin/amplify-runner"]
