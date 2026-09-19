.PHONY: all build test vet tidy pack docker update-rules clean

NAME := socksfilter
VERSION := $(shell git describe --tags --always 2>/dev/null || echo "0.4.0")
LDFLAGS := -s -w -X main.version=$(VERSION)

all: build

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(NAME) .

test:
	go test -v -race ./...

vet:
	go vet ./...

tidy:
	go mod tidy

pack:
	./pack.sh

docker:
	docker build -t esrrhs/socksfilter:latest .

update-rules:
	@echo "Updating accelerated-domains.china.conf from upstream..."
	curl -sL https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf -o accelerated-domains.china.conf
	@echo "Done. Domains: $$(wc -l < accelerated-domains.china.conf)"
	@echo "Updating GeoLite2-Country.mmdb from upstream..."
	curl -sL https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb -o GeoLite2-Country.mmdb
	@echo "Done. GeoLite2 size: $$(ls -lh GeoLite2-Country.mmdb | awk '{print $$5}')"

clean:
	rm -f $(NAME) $(NAME).exe pack.zip default_*.log socksfilter_*.log
	rm -rf pack/
