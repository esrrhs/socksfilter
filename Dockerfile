FROM golang AS build-env

RUN GO111MODULE=off go get -u github.com/esrrhs/socksfilter
RUN GO111MODULE=off go get -u github.com/esrrhs/socksfilter/...
RUN GO111MODULE=off go install github.com/esrrhs/socksfilter

FROM debian
COPY --from=build-env /go/bin/socksfilter .
COPY GeoLite2-Country.mmdb .
WORKDIR ./
