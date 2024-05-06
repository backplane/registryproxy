FROM alpine:edge
RUN apk add --no-cache ca-certificates
COPY --from=builder /registryproxy /

# this is only there if goreleaser has created it
COPY dist/registryproxy /usr/local/bin/registryproxy

# uncomment the following two lines if you're exposing a private GCR registry
# COPY key.json /key.json
# ENV GOOGLE_APPLICATION_CREDENTIALS /key.json

ENTRYPOINT [ "/usr/local/bin/registryproxy" ]
