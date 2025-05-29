@echo off

echo Check if go.mod exists...
if not exist go.mod (
    echo go.mod not found. Init mod.
    go mod init network-proxy
    go get gopkg.in/yaml.v3
)

echo Building...
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0
go build -ldflags "-s -w" -o local_proxy.exe main.go
