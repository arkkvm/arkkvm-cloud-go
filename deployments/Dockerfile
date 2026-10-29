# Multi-stage build: compile inside the container — the host needs no Go
# toolchain.
FROM golang:1.26-alpine AS build
# Module proxy is overridable for region-constrained builders: pass
# --build-arg GOPROXY=https://goproxy.cn,direct when building from CN.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/arkkvm-cloud ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/arkkvm-cloud /usr/local/bin/arkkvm-cloud
COPY configs /etc/arkkvm/configs
USER nonroot
EXPOSE 6612
ENTRYPOINT ["arkkvm-cloud", "-config-dir", "/etc/arkkvm/configs"]
