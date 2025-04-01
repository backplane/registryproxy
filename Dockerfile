FROM alpine:edge AS dist
ARG TARGETARCH TARGETOS

# this is only there if goreleaser has created it
COPY dist/registryproxy_${TARGETOS}_${TARGETARCH}*/registryproxy* /
RUN set -eux; \
  chmod +x /registryproxy;

FROM alpine:edge
LABEL maintainer="Backplane BV <backplane@users.noreply.github.com>"

# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates

COPY --from=dist /registryproxy /

ENTRYPOINT [ "/registryproxy" ]
