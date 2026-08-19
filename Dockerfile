# syntax=docker/dockerfile:1
FROM alpine:3.21 AS build
RUN apk add --no-cache gcc make musl-dev openssl-dev pkgconf
COPY src /src
RUN cc -O2 -pipe -Wall -Wextra -s -o /siloproxy \
    /src/main.c $(pkg-config --cflags --libs openssl) -pthread

FROM alpine:3.21
RUN apk add --no-cache libssl3 ca-certificates
COPY --from=build /siloproxy /siloproxy
EXPOSE 8080
USER 65534:65534
ENTRYPOINT ["/siloproxy"]
