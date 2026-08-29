# Build the fork with all standard modules, including the Alibaba Cloud CDN
# certificate event handler.
FROM golang:1.25-alpine AS builder

WORKDIR /src
RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/caddy ./cmd/caddy

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S caddy \
    && adduser -S -D -H -s /sbin/nologin -G caddy caddy \
    && mkdir -p /data/caddy /config/caddy \
    && chown -R caddy:caddy /data/caddy /config/caddy

COPY --from=builder /out/caddy /usr/bin/caddy

ENV XDG_DATA_HOME=/data \
    XDG_CONFIG_HOME=/config

USER caddy
EXPOSE 80 443 443/udp
VOLUME ["/data", "/config"]
ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
