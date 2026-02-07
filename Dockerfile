FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
LABEL maintainer="AkinoKaede"
COPY . /go/src/github.com/AkinoKaede/yori
WORKDIR /go/src/github.com/AkinoKaede/yori
ARG TARGETOS TARGETARCH
ARG TAGS="with_acme"
ARG GOPROXY=""
ENV GOPROXY ${GOPROXY}
ENV CGO_ENABLED=0
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
RUN set -ex \
    && apk add git build-base \
    && export VERSION=$(git describe --tags --always) \
    && go build -v -trimpath -tags "${TAGS}" \
        -o /go/bin/yori \
        -ldflags "-X 'github.com/AkinoKaede/yori/pkg/constant.Version=${VERSION}' -s -w -buildid=" \
        ./cmd/relay

FROM --platform=$TARGETPLATFORM alpine AS dist
LABEL maintainer="AkinoKaede"
RUN set -ex \
    && apk add --no-cache --upgrade bash tzdata ca-certificates \
    && rm -rf /var/cache/apk/*
COPY --from=builder /go/bin/yori /usr/local/bin/yori
ENTRYPOINT ["yori"]
