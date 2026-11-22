FROM gradle:8.12-jdk21 AS psi
WORKDIR /psi
COPY services/worker-kotlin/psi /psi
RUN gradle --no-daemon test shadowJar

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
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/service ./worker-kotlin

FROM eclipse-temurin:21-jre-alpine
COPY --from=build /out/service /service
COPY --from=psi /psi/build/libs/secflow-psi.jar /opt/secflow-psi.jar
ENV KOTLIN_PSI_JAR=/opt/secflow-psi.jar
USER 65532:65532
ENTRYPOINT ["/service"]
