FROM alpine:edge AS dist
ARG TARGETARCH TARGETOS
ARG NONROOT_UID=65532
ARG NONROOT_GID=65532

# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates

# goreleaser creates the dist tree
COPY dist/registryproxy_${TARGETOS}_${TARGETARCH}_*/registryproxy* /
RUN chmod +x /registryproxy;

# create the 'nonroot' account
RUN set -eux; \
  etc_build="/build/etc"; \
  mkdir -p "$etc_build"; \
  writeto() { output_file=$1; shift; printf '%s\n' "$*" >>"$output_file"; }; \
  writeto "${etc_build}/passwd"  "nonroot:x:${NONROOT_UID}:${NONROOT_GID}:nonroot:/home/nonroot:/sbin/nologin"; \
  writeto "${etc_build}/shadow"  "nonroot:*:18313:0:99999:7:::"; \
  writeto "${etc_build}/group"   "nonroot:x:${NONROOT_GID}:"; \
  writeto "${etc_build}/gshadow" "nonroot:::"; \
  :

FROM scratch
LABEL maintainer="Backplane BV <backplane@users.noreply.github.com>"

COPY --from=dist /build/etc/* /etc/
COPY --from=dist /etc/ssl /etc/ssl/
COPY --from=dist /registryproxy /

USER nonroot

ENTRYPOINT [ "/registryproxy" ]
