# One image for all roles: the stimmig binary and the voting client's bundle.
# The role is the command, for example "log", "registrar" or "ballotbox".
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/stimmig ./cmd/stimmig
# The same steps as "make web", into an empty directory.
RUN mkdir -p /out/client \
 && cp web/static/* /out/client/ \
 && cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" /out/client/ \
 && GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w -buildid=" -o /out/client/stimmig.wasm ./web/wasm

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/stimmig /stimmig
COPY --from=build /out/client /client
ENV STIMMIG_CLIENT_DIR=/client
EXPOSE 8080
ENTRYPOINT ["/stimmig"]
