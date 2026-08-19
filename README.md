# siloproxy

Reverse proxy that rewrites `Host` headers for SigV4 compatibility. Points at an upstream HTTPS service (like `onsilo.dev`), strips hop-by-hop headers, and streams responses back.

## Why

SigV4 signs the `Host` header. If your client signs for `localhost:8080` but the service expects `onsilo.dev`, you get `SignatureDoesNotMatch`. This proxy rotates the `Host` to match the upstream so signatures stay valid.

Point your S3 client at the proxy, but sign for the upstream host (`onsilo.dev`).

## Config

| Env var     | Default             | Purpose                                          |
|-------------|---------------------|--------------------------------------------------|
| `BIND`      | `0.0.0.0:8080`      | Listen address                                   |
| `UPSTREAM`  | `https://onsilo.dev` | Target (no trailing `/`)                         |
| `BUCKET`    | *all*               | Restrict to one bucket (first path segment). Else `403`. |
| `DEBUG`     | off                 | Log requests to stderr                           |

## Build

```sh
make            # or: cc -O2 -pipe -o siloproxy src/main.c $(pkg-config --cflags --libs openssl) -pthread
./siloproxy
```

Single C file, one OpenSSL dependency, ~0.5s compile. Thread per connection, 64KB streaming buffers, keepalive on both sides, chunked pass-through (no re-chunking), TLS upstream with SNI + cert verification.

Docker:

```sh
docker build -t siloproxy .
docker run -p 8080:8080 -e UPSTREAM=https://onsilo.dev siloproxy
```

Compose:

```yaml
services:
  siloproxy:
    image: ghcr.io/novarumsocial/siloproxy
    ports:
      - "8080:8080"
    environment:
      UPSTREAM: https://onsilo.dev
    restart: unless-stopped
```

Then `curl http://localhost:8080/some/path` proxies to `https://onsilo.dev/some/path`.
