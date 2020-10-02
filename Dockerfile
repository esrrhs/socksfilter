FROM golang AS build-env

RUN go get -u github.com/esrrhs/socksfilter
RUN go get -u github.com/esrrhs/socksfilter/...
RUN go install github.com/esrrhs/socksfilter

FROM debian
COPY --from=build-env /go/bin/socksfilter .
WORKDIR ./
