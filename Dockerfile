FROM golang:1-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
RUN go build -o /registryproxy

FROM alpine
RUN apk add --no-cache ca-certificates
COPY --from=builder /registryproxy /

# uncomment the following two lines if you're exposing a private GCR registry
# COPY key.json /key.json
# ENV GOOGLE_APPLICATION_CREDENTIALS /key.json

ENTRYPOINT [ "/registryproxy" ]
