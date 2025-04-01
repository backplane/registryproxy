FROM alpine:edge AS dist
ARG TARGETARCH TARGETOS

# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates

# goreleaser creates the dist tree
COPY dist/registryproxy_${TARGETOS}_${TARGETARCH}_*/registryproxy* /
RUN chmod +x /registryproxy;

FROM scratch
LABEL maintainer="Backplane BV <backplane@users.noreply.github.com>"

COPY --from=dist /etc/ssl /etc/ssl/
COPY --from=dist /registryproxy /

ENTRYPOINT [ "/registryproxy" ]
