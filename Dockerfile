FROM alpine:edge as dist
ARG TARGETPLATFORM

# this is only there if goreleaser has created it
COPY dist /dist/
RUN set -eux; \
  subdir=$(printf '/dist/cli_%s' "${TARGETPLATFORM}" | tr / _ | tr A-Z a-z); \
  cp ${subdir}/registryproxy /registryproxy;

FROM alpine:edge
RUN apk add --no-cache ca-certificates
COPY --from=dist /registryproxy /

ENTRYPOINT [ "/registryproxy" ]
