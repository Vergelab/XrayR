# Build go
FROM golang:1.27.3-alpine AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
ARG XRAYR_VERSION=0.4
RUN go mod download \
    && go build -v -o XrayR -trimpath -ldflags "-s -w -buildid= -X github.com/Vergelab/XrayR/cmd.version=${XRAYR_VERSION} -X github.com/Vergelab/XrayR/cmd.buildBy=Vergelab"

# Release
FROM alpine:3.24.3
# 安装必要的工具包。curl -f 让 geo 文件的 404 失败而不是写成空文件。
RUN apk --update --no-cache add curl tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && mkdir -p /etc/XrayR/ \
    && curl -fL "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat" -o /etc/XrayR/geoip.dat \
    && curl -fL "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat" -o /etc/XrayR/geosite.dat \
    && addgroup -S xrayr \
    && adduser -S -D -H -G xrayr xrayr \
    && chown -R xrayr:xrayr /etc/XrayR

COPY --from=builder /app/XrayR /usr/local/bin

USER xrayr
ENTRYPOINT [ "XrayR", "--config", "/etc/XrayR/config.yml"]
