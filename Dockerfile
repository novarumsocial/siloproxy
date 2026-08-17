# syntax=docker/dockerfile:1
FROM rust:1-alpine AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN apk add --no-cache ca-certificates \
    && cargo build --release \
    && mv target/release/siloproxy /siloproxy

FROM scratch
COPY --from=build /siloproxy /siloproxy
COPY --from=build /etc/ssl/certs /etc/ssl/certs
COPY --from=build /etc/ssl/cert.pem /etc/ssl/cert.pem
EXPOSE 8080
USER 65534:65534
ENTRYPOINT ["/siloproxy"]