# Merlin version
VERSION=$(shell cat pkg/merlin.go |grep "const Version ="|cut -d"\"" -f2)
BUILD=$(shell git rev-parse HEAD)

# Output File Location
DIR=data/temp/v${VERSION}/${BUILD}
$(shell mkdir -p ${DIR})

# Go build flags
LDFLAGS=-ldflags '-X main.build=${BUILD} -buildid='

default:
	go build ${LDFLAGS} -o ${DIR}/${MSERVER} main.go

# Compile Server - Windows x64
windows:
	export GOOS=windows;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/merlinServer-Windows-x64.exe main.go

# Compile Server - Linux x64
linux:
	export GOOS=linux;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/merlinServer-Linux-x64 main.go

# Compile Server - Darwin x64
darwin:
	export GOOS=darwin;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/merlinServer-Darwin-x64 main.go

clean:
	rm -rf ${DIR}*
