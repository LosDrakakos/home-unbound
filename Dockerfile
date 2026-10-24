# syntax=docker/dockerfile:1
ARG ALPINE_VERSION=3.24.3
ARG GO_IMAGE=golang:1.27.3-alpine3.24

FROM alpine:${ALPINE_VERSION} AS unbound-build
ARG UNBOUND_VERSION=latest
ARG UNBOUND_MIN_VERSION=1.26.2
ARG UNBOUND_SHA256=
RUN apk add --no-cache build-base ca-certificates curl file gnupg openssl-dev openssl-libs-static expat-dev expat-static libevent-dev libevent-static
WORKDIR /build
COPY build/fetch-unbound.sh /build/fetch-unbound.sh
COPY build/keys/nlnetlabs-releases-g2.asc /build/keys/nlnetlabs-releases-g2.asc
ADD https://nlnetlabs.nl/downloads/unbound/ /build/unbound-index.html
RUN UNBOUND_VERSION="$UNBOUND_VERSION" \
    UNBOUND_MIN_VERSION="$UNBOUND_MIN_VERSION" \
    UNBOUND_SHA256="$UNBOUND_SHA256" \
    UNBOUND_INDEX_FILE=/build/unbound-index.html \
    UNBOUND_KEY_FILE=/build/keys/nlnetlabs-releases-g2.asc \
    UNBOUND_TARGET_DIR=/build/unbound-src \
    UNBOUND_VERSION_FILE=/build/UNBOUND_VERSION \
    sh /build/fetch-unbound.sh
WORKDIR /build/unbound-src
RUN LDFLAGS="-static" ./configure \
      --prefix=/usr/local \
      --sysconfdir=/etc \
      --localstatedir=/var \
      --with-pidfile="" \
      --with-username="" \
      --with-chroot-dir="" \
      --with-ssl=/usr \
      --with-libexpat=/usr \
      --with-libevent=/usr \
      --enable-fully-static \
      --enable-static \
      --disable-shared \
      --without-pythonmodule \
      --without-pyunbound \
      --without-libhiredis \
      --without-libnghttp2 \
      --disable-dnstap \
      --disable-systemd \
 && make -j"$(getconf _NPROCESSORS_ONLN)" \
 && make install DESTDIR=/out \
 && strip /out/usr/local/sbin/unbound /out/usr/local/sbin/unbound-checkconf /out/usr/local/sbin/unbound-anchor \
 && check_static() { \
      binary="$1"; \
      readelf -hW "$binary" >/dev/null || { echo "$binary is not a readable ELF binary" >&2; return 1; }; \
      if readelf -lW "$binary" | grep -Eq 'INTERP|Requesting program interpreter'; then echo "$binary has a program interpreter" >&2; return 1; fi; \
      if readelf -dW "$binary" 2>/dev/null | grep -q '(NEEDED)'; then echo "$binary has a dynamic dependency" >&2; return 1; fi; \
    } \
 && for binary in unbound unbound-checkconf unbound-anchor; do \
      check_static "/out/usr/local/sbin/$binary"; \
    done
RUN set +e; /out/usr/local/sbin/unbound-anchor -a /build/root.key; rc=$?; set -e; \
    if [ "$rc" -gt 1 ]; then echo "unbound-anchor failed with status $rc" >&2; exit "$rc"; fi; \
    test -s /build/root.key; \
    grep -Eq '(^|[[:space:];])20326([[:space:];]|$)' /build/root.key; \
    grep -Eq '(^|[[:space:];])38696([[:space:];]|$)' /build/root.key

FROM ${GO_IMAGE} AS manager-build
WORKDIR /src
RUN apk add --no-cache binutils
COPY manager/go.mod ./
COPY manager/ ./
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=mod
RUN go vet ./... && go test ./...
ARG VERSION=dev
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/unbound-manager ./cmd/unbound-manager \
 && check_static() { \
      binary="$1"; \
      readelf -hW "$binary" >/dev/null || { echo "$binary is not a readable ELF binary" >&2; return 1; }; \
      if readelf -lW "$binary" | grep -Eq 'INTERP|Requesting program interpreter'; then echo "$binary has a program interpreter" >&2; return 1; fi; \
      if readelf -dW "$binary" 2>/dev/null | grep -q '(NEEDED)'; then echo "$binary has a dynamic dependency" >&2; return 1; fi; \
    } \
 && check_static /out/unbound-manager

FROM alpine:${ALPINE_VERSION} AS rootfs
RUN mkdir -p /rootfs/usr/local/sbin /rootfs/usr/local/bin /rootfs/etc/unbound/custom.d /rootfs/data/unbound /rootfs/data/manager /rootfs/run/unbound \
 && printf 'unbound:x:10053:10053:Unbound resolver:/data:/sbin/nologin\n' > /rootfs/etc/passwd \
 && printf 'unbound:x:10053:\n' > /rootfs/etc/group \
 && chown -R 10053:10053 /rootfs/data /rootfs/run/unbound \
 && chmod 0750 /rootfs/data /rootfs/data/unbound /rootfs/data/manager /rootfs/run/unbound
COPY --from=unbound-build /out/usr/local/sbin/unbound /out/usr/local/sbin/unbound-checkconf /rootfs/usr/local/sbin/
COPY --from=unbound-build /build/root.key /rootfs/etc/unbound/root.key.seed
COPY --from=manager-build /out/unbound-manager /rootfs/usr/local/bin/unbound-manager
COPY config/unbound.conf /rootfs/etc/unbound/unbound.conf
COPY config/custom.d/ /rootfs/etc/unbound/custom.d/
RUN chmod 0555 /rootfs/usr/local/sbin/* /rootfs/usr/local/bin/unbound-manager \
 && chmod 0444 /rootfs/etc/unbound/unbound.conf /rootfs/etc/unbound/root.key.seed /rootfs/etc/unbound/custom.d/*

FROM scratch
COPY --from=rootfs /rootfs/ /
USER 10053:10053
EXPOSE 53/udp 53/tcp 8080/tcp
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/unbound-manager"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --start-interval=2s --retries=3 CMD ["/usr/local/bin/unbound-manager", "healthcheck"]
