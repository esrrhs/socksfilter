# Build stage
FROM golang:alpine AS build-env

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o socksfilter .

# Final stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=build-env /app/socksfilter /app/socksfilter
COPY GeoLite2-Country.mmdb /app/GeoLite2-Country.mmdb
COPY accelerated-domains.china.conf /app/accelerated-domains.china.conf

EXPOSE 1080

ENTRYPOINT ["/app/socksfilter"]
CMD ["-h"]
