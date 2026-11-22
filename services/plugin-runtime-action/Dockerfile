FROM golang:1.27.4-alpine AS builder
WORKDIR /src
COPY packages/proto ./packages/proto
COPY services/go.mod services/go.sum ./services/
WORKDIR /src/services
RUN go mod download
COPY services .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/plugin-runtime-action ./plugin-runtime-action

FROM gcr.io/distroless/static-debian12:nonroot
USER 65532:65532
COPY --from=builder /out/plugin-runtime-action /usr/local/bin/plugin-runtime-action
EXPOSE 8091
ENTRYPOINT ["/usr/local/bin/plugin-runtime-action"]
