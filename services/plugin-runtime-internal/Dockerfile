FROM golang:1.27.4-alpine AS builder
WORKDIR /src
COPY packages/proto ./packages/proto
COPY services/go.mod services/go.sum ./services/
WORKDIR /src/services
RUN go mod download
COPY services .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/plugin-runtime-internal ./plugin-runtime-internal

FROM gcr.io/distroless/static-debian12:nonroot
USER 65532:65532
COPY --from=builder /out/plugin-runtime-internal /usr/local/bin/plugin-runtime-internal
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/plugin-runtime-internal"]
