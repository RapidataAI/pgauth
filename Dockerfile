FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/pgauth ./cmd/pgauth

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pgauth /pgauth
USER nonroot:nonroot
EXPOSE 5432 8080
ENTRYPOINT ["/pgauth"]
CMD ["serve", "--config", "/etc/pgauth/config.yaml"]
