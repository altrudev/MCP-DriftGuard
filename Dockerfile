FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mcpdrift ./cmd/mcpdrift

FROM alpine:3.21
RUN adduser -D -H -u 10001 mcpdrift
COPY --from=build /out/mcpdrift /usr/local/bin/mcpdrift
USER mcpdrift
ENTRYPOINT ["/usr/local/bin/mcpdrift"]
