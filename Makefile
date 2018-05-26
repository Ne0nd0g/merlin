# !!!MAKE SURE YOUR GOPATH ENVIRONMENT VARIABLE IS SET FIRST!!!

# Merlin Server & Agent version number
VERSION=0.5.0

MSERVER=merlinServer
MAGENT=merlinAgent
PASSWORD=merlin
BUILD=$(shell git rev-parse HEAD)
DIR=data/temp/v${VERSION}/
BIN=data/bin/
LDFLAGS=-ldflags "-s -X main.build=${BUILD}"
WINAGENTLDFLAGS=-ldflags "-s -X main.build=${BUILD} -H=windowsgui"
PACKAGE=7za a -p${PASSWORD} -mhe -mx=9
F=README.MD LICENSE data/modules docs data/README.MD data/agents/README.MD data/db/ data/log/README.MD data/x509 data/src data/bin
F2=LICENSE
W=Windows-x64
L=Linux-x64
A=Linux-arm
M=Linux-mips
D=Darwin-x64

# Make Directory to store executables
$(shell mkdir -p ${DIR})

# Change default to just make for the host OS and add MAKE ALL to do this
default: server-windows agent-windows server-linux agent-linux server-darwin agent-darwin agent-dll

all: default

# Compile Windows binaries
windows: server-windows agent-windows agent-dll

# Compile Linux binaries
linux: server-linux agent-linux

# Compile Arm binaries
arm: agent-arm

# Compile mips binaries
mips: agent-mips

# Compile Darwin binaries
darwin: server-darwin agent-darwin

# Compile Server - Windows x64
server-windows:
	export GOOS=windows;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MSERVER}-${W}.exe cmd/merlinserver/main.go

# Compile Agent - Windows x64
agent-windows:
	export GOOS=windows GOARCH=amd64;go build ${WINAGENTLDFLAGS} -o ${DIR}/${MAGENT}-${W}.exe cmd/merlinagent/main.go

# Compile Agent - Windows x64 DLL
agent-dll:
	export GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ CGO_ENABLED=1; \
	go build -buildmode=c-archive -o ${DIR}/main.a cmd/merlinagentdll/main.go; \
	cp data/bin/dll/merlin.c ${DIR}; \
	x86_64-w64-mingw32-gcc -shared -pthread -o ${DIR}merlin.dll ${DIR}merlin.c ${DIR}main.a -lwinmm -lntdll -lws2_32

# Compile Server - Linux x64
server-linux:
	export GOOS=linux;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MSERVER}-${L} cmd/merlinserver/main.go

# Compile Agent - Linux mips
agent-mips:
	export GOOS=linux;export GOARCH=mips;go build ${LDFLAGS} -o ${DIR}/${MAGENT}-${M} cmd/merlinagent/main.go

# Compile Agent - Linux arm
agent-arm:
	export GOOS=linux;export GOARCH=arm;export GOARM=7;go build ${LDFLAGS} -o ${DIR}/${MAGENT}-${A} cmd/merlinagent/main.go

# Compile Agent - Linux x64
agent-linux:
	export GOOS=linux;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MAGENT}-${L} cmd/merlinagent/main.go
	
# Compile Server - Darwin x64
server-darwin:
	export GOOS=darwin;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MSERVER}-${D}.dmg cmd/merlinserver/main.go

# Compile Agent - Darwin x64
agent-darwin:
	export GOOS=darwin;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MAGENT}-${D}.dmg cmd/merlinagent/main.go

# Make directory 'data' and then agents, db, log, x509; Copy src folder, README, and requirements
package-server-windows:
	${PACKAGE} ${DIR}${MSERVER}-${W}-v${VERSION}.7z ${F}
	cd ${DIR};${PACKAGE} ${MSERVER}-${W}-v${VERSION}.7z ${MSERVER}-${W}.exe

package-server-linux:
	${PACKAGE} ${DIR}${MSERVER}-${L}-v${VERSION}.7z ${F}
	cd ${DIR};${PACKAGE} ${MSERVER}-${L}-v${VERSION}.7z ${MSERVER}-${L}

package-server-darwin:
	${PACKAGE} ${DIR}${MSERVER}-${D}-v${VERSION}.7z ${F}
	cd ${DIR};${PACKAGE} ${MSERVER}-${D}-v${VERSION}.7z ${MSERVER}-${D}.dmg

package-agent-windows:
	${PACKAGE} ${DIR}${MAGENT}-${W}-v${VERSION}.7z ${F2}
	cd ${DIR};${PACKAGE} ${MAGENT}-${W}-v${VERSION}.7z ${MAGENT}-${W}.exe
	cp ${DIR}${MAGENT}-${W}.exe ${BIN}windows

package-agent-linux:
	${PACKAGE} ${DIR}${MAGENT}-${L}-v${VERSION}.7z ${F2}
	cd ${DIR};${PACKAGE} ${MAGENT}-${L}-v${VERSION}.7z ${MAGENT}-${L}
	cp ${DIR}${MAGENT}-${L} ${BIN}linux
	
package-agent-darwin:
	${PACKAGE} ${DIR}${MAGENT}-${D}-v${VERSION}.7z ${F2}
	cd ${DIR};${PACKAGE} ${MAGENT}-${D}-v${VERSION}.7z ${MAGENT}-${D}.dmg
	cp ${DIR}${MAGENT}-${D}.dmg ${BIN}darwin

package-agent-dll:
	${PACKAGE} ${DIR}${MAGENT}-DLL-v${VERSION}.7z ${F2}
	cd ${DIR};${PACKAGE} ${MAGENT}-DLL-v${VERSION}.7z merlin.dll
	cp ${DIR}merlin.dll ${BIN}dll

package-all: package-agent-windows package-agent-dll package-agent-linux package-agent-darwin package-server-windows package-server-linux package-server-darwin

clean:
	rm -rf ${DIR}*

#Build all files for release distribution
distro: clean all package-all
