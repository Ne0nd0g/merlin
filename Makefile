# Merlin version
VERSION=$(shell cat pkg/merlin.go |grep "const Version ="|cut -d"\"" -f2)
BUILD=$(shell git rev-parse HEAD)

MSERVER=merlinServer

# Output File Location
DIR=data/temp/v${VERSION}/${BUILD}
$(shell mkdir -p ${DIR})

# Go build flags
LDFLAGS=-ldflags '-s -w -X main.build=${BUILD} -buildid='

# Packaging
PASSWORD=merlin
PACKAGE=7za a -p${PASSWORD} -mhe -mx=9
F=README.MD LICENSE data/modules docs data/README.MD data/agents/README.MD data/db/ data/log/README.MD data/x509 data/src data/bin data/html

default:
	go build ${LDFLAGS} -o ${DIR}/${MSERVER} main.go

# Compile Server - Windows x64
windows:
	export GOOS=windows;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MSERVER}-Windows-x64.exe main.go

# Compile Server - Linux x64
linux:
	export GOOS=linux;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MSERVER}-Linux-x64 main.go

# Compile Server - Darwin x64
darwin:
	export GOOS=darwin;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MSERVER}-Darwin-x64 main.go

package: default package-server

package-server:
	${PACKAGE} ${DIR}/${MSERVER}.7z ${F}
	cd ${DIR};${PACKAGE} ${MSERVER}.7z ${MSERVER}.exe

package-server-windows:
	${PACKAGE} ${DIR}/${MSERVER}-${W}.7z ${F}
	cd ${DIR};${PACKAGE} ${MSERVER}-${W}.7z ${MSERVER}-${W}.exe

package-server-linux:
	${PACKAGE} ${DIR}/${MSERVER}-${L}.7z ${F}
	cd ${DIR};${PACKAGE} ${MSERVER}-${L}.7z ${MSERVER}-${L}

package-server-darwin:
	${PACKAGE} ${DIR}/${MSERVER}-${D}.7z ${F}
	cd ${DIR};${PACKAGE} ${MSERVER}-${D}.7z ${MSERVER}-${D}

clean:
	rm -rf ${DIR}*
