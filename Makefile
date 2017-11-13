# Merlin Server & Agent version number
VERSION=0.1.2

MSERVER=merlinServer
MAGENT=merlinAgent
BUILD=$(shell git rev-parse HEAD)
DIR=data/bin/v${VERSION}/
GOPATH := ${PWD}/_vendor:${GOPATH}
LDFLAGS=-ldflags "-X main.version=${VERSION} -X main.build=${BUILD}"
WINAGENTLDFLAGS=-ldflags "-X main.version=${VERSION} -X main.build=${BUILD} -H=windowsgui"

export GOPATH

# Make Directory to store executables
$(shell mkdir -p ${DIR})

# Change default to just make for the host OS and add MAKE ALL to do this
default: server-windows agent-windows server-linux agent-linux server-darwin agent-darwin

all: default

# Complile Windows binaries
windows: server-windows agent-windows

# Compile Linux binaries
linux: server-linux agent-linux

# Compile Darwin binaries
darwin: server-darwin agent-darwin

# Compile Server - Windows x64
server-windows:
	export GOOS=windows;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MSERVER}-Windows-x64.exe cmd/merlinserver/main.go

# Compile Agent - Windows x64
agent-windows:

	export GOOS=windows;export GOARCH=amd64;go build ${WINAGENTLDFLAGS} -o ${DIR}/${MAGENT}-Windows-x64.exe cmd/merlinagent/main.go

# Compile Server - Linux x64
server-linux:
	export GOOS=linux;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MSERVER}-Linux-x64 cmd/merlinserver/main.go

# Compile Agent - Linux x64
agent-linux:

	export GOOS=linux;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MAGENT}-Linux-x64 cmd/merlinagent/main.go
	
# Compile Server - Darwin x64
server-darwin:
	export GOOS=darwin;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MSERVER}-Darwin-x64.dmg cmd/merlinserver/main.go

# Compile Agent - Darwin x64
agent-darwin:

	export GOOS=darwin;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MAGENT}-Darwin-x64.dmg cmd/merlinagent/main.go

# Make directory 'data' and then agents, db, log, x509; Copy src folder, README, and requirements
tar-server-windows:

	cd ${DIR};tar -zcvf ${MSERVER}-Windows-x64-v${VERSION}.tar.gz ${MSERVER}-Windows-x64.exe ../../../data/README.MD ../../../data/requirements.txt ../../../data/db ../../../data/log ../../../data/src ../../../data/x509 ../../../data/agents/README.MD
	
tar-server-linux:
	cd ${DIR};tar -zcvf ${MSERVER}-Linux-x64-v${VERSION}.tar.gz ${MSERVER}-Linux-x64 ../../../data/README.MD ../../../data/requirements.txt ../../../data/db ../../../data/log ../../../data/src ../../../data/x509 ../../../data/agents/README.MD
	
tar-server-darwin:
	cd ${DIR};tar -zcvf ${MSERVER}-Darwin-x64-v${VERSION}.tar.gz ${MSERVER}-Darwin-x64.dmg ../../../data/README.MD ../../../data/requirements.txt ../../../data/db ../../../data/log ../../../data/src ../../../data/x509 ../../../data/agents/README.MD

tar-agent-windows:
	cd ${DIR};tar -zcvf ${MAGENT}-Windows-x64-v${VERSION}.tar.gz ${MAGENT}-Windows-x64.exe

tar-agent-linux:
	cd ${DIR};tar -zcvf ${MAGENT}-Linux-x64-v${VERSION}.tar.gz ${MAGENT}-Linux-x64
	
tar-agent-darwin:
	cd ${DIR};tar -zcvf ${MAGENT}-Darwin-x64-v${VERSION}.tar.gz ${MAGENT}-Darwin-x64.dmg
	
tar-all: tar-server-windows tar-server-linux tar-server-darwin tar-agent-windows tar-agent-linux tar-agent-darwin

clean:
	$(RM) ${DIR}/merlin*

#Build all files for release distrobution
distro: clean all tar-all
