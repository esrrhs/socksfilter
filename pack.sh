#!/usr/bin/env bash
set -e

NAME="socksfilter"
DATA_FILES=("GeoLite2-Country.mmdb" "accelerated-domains.china.conf" "README.md" "LICENSE")
VERSION=$(git describe --tags --always 2>/dev/null || echo "0.5.0")
LDFLAGS="-s -w -X main.version=${VERSION}"

export CGO_ENABLED=0

rm -rf pack pack.zip
mkdir -p pack

# Build common platforms by default, or all if BUILD_ALL=1
if [ "${BUILD_ALL}" = "1" ]; then
  build_list=$(go tool dist list | grep -v -E "android|ios|wasm")
else
  build_list="linux/amd64 linux/arm64 linux/arm windows/amd64 windows/arm64 darwin/amd64 darwin/arm64"
fi

for target in $build_list; do
  os=$(echo "$target" | cut -d'/' -f1)
  arch=$(echo "$target" | cut -d'/' -f2)

  echo "==> Building ${NAME} for ${os}/${arch}..."
  binary="${NAME}"
  if [ "${os}" = "windows" ]; then
    binary="${NAME}.exe"
  fi

  GOOS="${os}" GOARCH="${arch}" go build -ldflags="${LDFLAGS}" -o "${binary}" .

  zip_name="${NAME}_${os}_${arch}.zip"
  zip -q -j "${zip_name}" "${binary}" "${DATA_FILES[@]}"
  mv "${zip_name}" pack/
  rm -f "${binary}"

  echo "    Packaged ${zip_name}"
done

echo "==> Creating master pack.zip..."
(cd pack && zip -q -r ../pack.zip .)

echo "==> All builds completed successfully in pack/"
