FROM golang:1.27.4-bookworm AS build
WORKDIR /src
COPY packages/proto/go.mod packages/proto/go.sum /src/packages/proto/
COPY services/go.mod services/go.sum /src/services/
WORKDIR /src/services
RUN go mod download
WORKDIR /src
COPY packages/proto /src/packages/proto
COPY services /src/services
WORKDIR /src/services
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/service ./sbom-service

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/service /service
USER nonroot:nonroot
ENTRYPOINT ["/service"]
