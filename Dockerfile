# One image for all roles: the stimmig binary and the voting client's bundle.
# The role is the command, for example "log", "registrar" or "ballotbox".
# Images are pinned by digest: a changed image changes the build, and the Go
# version changes the bytes of the voting client and so its hash.
FROM golang:1.25@sha256:699337d620559a59b4a2bb298ad59611e535d2ee755a34cf2d2a98f37578dc80 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/stimmig ./cmd/stimmig
# The same steps as "make web", into an empty directory.
RUN mkdir -p /out/client \
 && cp web/static/* /out/client/ \
 && cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" /out/client/ \
 && GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/client/stimmig.wasm ./web/wasm

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/stimmig /stimmig
COPY --from=build /out/client /client
ENV STIMMIG_CLIENT_DIR=/client
EXPOSE 8080
ENTRYPOINT ["/stimmig"]
