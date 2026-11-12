# The voting client's bundle: the static files, Go's WebAssembly loader and
# the client compiled to WebAssembly. The build is reproducible for a given
# Go version; the manifest of an election publishes the hash of the bundle.
# Build into an empty web/dist: files left there from before change the hash.
web:
	mkdir -p web/dist
	cp web/static/* web/dist/
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" web/dist/
	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w -buildid=" -o web/dist/stimmig.wasm ./web/wasm

.PHONY: web
