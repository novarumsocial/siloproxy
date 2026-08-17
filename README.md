# siloproxy

Minimal reverse proxy that forwards requests to an upstream HTTPS service,
keeping the client's `Host` header and path intact so SigV4-signed requests
keep working.

## How it works

For each request it builds `{UPSTREAM}{path}`, strips hop-by-hop headers
(`Connection`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`), forwards the
rest unchanged, and streams the response back. TLS is handled with native root
certificates.

## Configuration

| Env var   | Default            | Description                          |
|-----------|--------------------|--------------------------------------|
| `BIND`    | `0.0.0.0:8080`     | Address to listen on                 |
| `UPSTREAM`| `https://onsilo.dev`| Target to proxy to (no trailing `/`) |

## Run with Docker

```sh
docker build -t siloproxy .
docker run -p 8080:8080 \
  -e BIND=0.0.0.0:8080 \
  -e UPSTREAM=https://onsilo.dev \
  siloproxy
```

## Docker Compose

```yaml
services:
  siloproxy:
    build: .
    ports:
      - "8080:8080"
    environment:
      BIND: 0.0.0.0:8080
      UPSTREAM: https://onsilo.dev
    restart: unless-stopped
```

Then `curl http://localhost:8080/some/path` proxies to
`https://onsilo.dev/some/path`.

## Run from source

```sh
cargo run --release
```