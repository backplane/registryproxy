FROM alpine:edge as dist
ARG TARGETPLATFORM

# this is only there if goreleaser has created it
COPY dist /dist/
RUN set -eux; \
  platform_dirname=$(printf '%s' "${TARGETPLATFORM}" | tr / _ | tr A-Z a-z | sed 's/amd64_v1/amd64/g'); \
  subdir=$(printf '/dist/cli_%s' $platform_dirname); \
  cp ${subdir}/registryproxy /registryproxy;

FROM alpine:edge
RUN apk add --no-cache ca-certificates
COPY --from=dist /registryproxy /

ENTRYPOINT [ "/registryproxy" ]
