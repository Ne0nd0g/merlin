# !!!MAKE SURE YOUR GOPATH ENVIRONMENT VARIABLE IS SET FIRST!!!

# Merlin Server & Agent version number
VERSION=$(shell cat pkg/merlin.go |grep "const Version ="|cut -d"\"" -f2)

MSERVER=merlinServer
MAGENT=merlinAgent
PASSWORD=merlin
BUILD=$(shell git rev-parse HEAD)
DIR=data/temp/v${VERSION}/${BUILD}
BIN=data/bin/
XBUILD=-X main.build=${BUILD} -X github.com/Ne0nd0g/merlin/pkg/agent.build=${BUILD}
URL ?= https://127.0.0.1:443
XURL=-X main.url=${URL}
PSK ?= merlin
XPSK=-X main.psk=${PSK}
PROXY ?=
XPROXY =-X main.proxy=$(PROXY)
HOST ?=
XHOST =-X main.host=$(HOST)
PROTO ?= h2
XPROTO =-X main.protocol=$(PROTO)
LDFLAGS=-ldflags "-s -w ${XBUILD} ${XPROTO} ${XURL} ${XHOST} ${XPSK} ${XPROXY} -buildid="
WINAGENTLDFLAGS=-ldflags "-s -w ${XBUILD} ${XPROTO} ${XURL} ${XHOST} ${XPSK} ${XPROXY} -H=windowsgui -buildid="
# TODO Update when Go1.13 is released https://stackoverflow.com/questions/45279385/remove-file-paths-from-text-directives-in-go-binaries
GCFLAGS=-gcflags=all=-trimpath=$(GOPATH)
ASMFLAGS=-asmflags=all=-trimpath=$(GOPATH)# -asmflags=-trimpath=$(GOPATH)
PACKAGE=7za a -p${PASSWORD} -mhe -mx=9
F=README.MD LICENSE data/modules docs data/README.MD data/agents/README.MD data/db/ data/log/README.MD data/x509 data/src data/bin data/html
F2=LICENSE
W=Windows-x64
L=Linux-x64
A=Linux-arm
M=Linux-mips
D=Darwin-x64
export GO111MODULE=on

# Make Directory to store executables
$(shell mkdir -p ${DIR})

# Change default to just make for the host OS and add MAKE ALL to do this
default: server-windows agent-windows server-linux agent-linux server-darwin agent-darwin agent-dll agent-javascript prism-windows prism-linux prism-darwin

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
	export GOOS=windows GOARCH=amd64;go build ${WINAGENTLDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/${MAGENT}-${W}.exe cmd/merlinagent/main.go

# Compile Agent - Windows x64 DLL - main() - Console
agent-dll:
	export GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ CGO_ENABLED=1; \
	go build ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -buildmode=c-archive -o ${DIR}/main.a cmd/merlinagentdll/main.go; \
	cp data/bin/dll/merlin.c ${DIR}; \
	x86_64-w64-mingw32-gcc -shared -pthread -o ${DIR}/merlin.dll ${DIR}/merlin.c ${DIR}/main.a -lwinmm -lntdll -lws2_32

# Compile PRISM - Windows x64
prism-windows:
	export GOOS=windows GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/PRISM-${W}.exe cmd/prism/main.go

# Compile Server - Linux x64
server-linux:
	export GOOS=linux;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MSERVER}-${L} cmd/merlinserver/main.go

# Compile Agent - Linux mips
agent-mips:
	export GOOS=linux;export GOARCH=mips;go build ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/${MAGENT}-${M} cmd/merlinagent/main.go

# Compile Agent - Linux arm
agent-arm:
	export GOOS=linux;export GOARCH=arm;export GOARM=7;go build ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/${MAGENT}-${A} cmd/merlinagent/main.go

# Compile Agent - Linux x64
agent-linux:
	export GOOS=linux;export GOARCH=amd64;go build ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/${MAGENT}-${L} cmd/merlinagent/main.go

# Compile PRISM - Linux x64
prism-linux:
	export GOOS=linux;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/PRISM-${L} cmd/prism/main.go

# Compile Server - Darwin x64
server-darwin:
	export GOOS=darwin;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/${MSERVER}-${D} cmd/merlinserver/main.go

# Compile Agent - Darwin x64
agent-darwin:
	export GOOS=darwin;export GOARCH=amd64;go build ${LDFLAGS} ${GCFLAGS} ${ASMFLAGS} -o ${DIR}/${MAGENT}-${D} cmd/merlinagent/main.go

# Compile PRISM - Darwin x64
prism-darwin:
	export GOOS=darwin;export GOARCH=amd64;go build ${LDFLAGS} -o ${DIR}/PRISM-${D} cmd/prism/main.go

# Update JavaScript Information
agent-javascript:
	sed -i 's/var build = ".*"/var build = "${BUILD}"/' data/html/scripts/merlin.js
	sed -i 's/var version = ".*"/var version = "${VERSION}"/' data/html/scripts/merlin.js
	sed -i 's|var url = ".*"|var url = "${URL}"|' data/html/scripts/merlin.js

# Make directory 'data' and then agents, db, log, x509; Copy src folder, README, and requirements
package-server-windows:
	${PACKAGE} ${DIR}/${MSERVER}-${W}-v${VERSION}.7z ${F}
	cd ${DIR};${PACKAGE} ${MSERVER}-${W}-v${VERSION}.7z ${MSERVER}-${W}.exe

package-server-linux:
	${PACKAGE} ${DIR}/${MSERVER}-${L}-v${VERSION}.7z ${F}
	cd ${DIR};${PACKAGE} ${MSERVER}-${L}-v${VERSION}.7z ${MSERVER}-${L}

package-server-darwin:
	${PACKAGE} ${DIR}/${MSERVER}-${D}-v${VERSION}.7z ${F}
	cd ${DIR};${PACKAGE} ${MSERVER}-${D}-v${VERSION}.7z ${MSERVER}-${D}

package-agent-windows:
	${PACKAGE} ${DIR}/${MAGENT}-${W}-v${VERSION}.7z ${F2}
	cd ${DIR};${PACKAGE} ${MAGENT}-${W}-v${VERSION}.7z ${MAGENT}-${W}.exe
	mkdir -p ${BIN}windows
	cp ${DIR}/${MAGENT}-${W}.exe ${BIN}windows/

package-agent-linux:
	${PACKAGE} ${DIR}/${MAGENT}-${L}-v${VERSION}.7z ${F2}
	cd ${DIR};${PACKAGE} ${MAGENT}-${L}-v${VERSION}.7z ${MAGENT}-${L}
	mkdir -p ${BIN}linux
	cp ${DIR}/${MAGENT}-${L} ${BIN}linux/
	
package-agent-darwin:
	${PACKAGE} ${DIR}/${MAGENT}-${D}-v${VERSION}.7z ${F2}
	cd ${DIR};${PACKAGE} ${MAGENT}-${D}-v${VERSION}.7z ${MAGENT}-${D}
	mkdir -p ${BIN}darwin/
	cp ${DIR}/${MAGENT}-${D} ${BIN}darwin/

package-agent-dll:
	${PACKAGE} ${DIR}/${MAGENT}-DLL-v${VERSION}.7z ${F2}
	cd ${DIR};${PACKAGE} ${MAGENT}-DLL-v${VERSION}.7z merlin.dll
	cp ${DIR}/merlin.dll ${BIN}dll

package-prism-windows:
	${PACKAGE} ${DIR}/PRISM-${W}-v${VERSION}.7z ${F2}
	cd ${DIR};${PACKAGE} PRISM-${W}-v${VERSION}.7z PRISM-${W}.exe
	cp ${DIR}/PRISM-${W}.exe ${BIN}windows/

package-prism-linux:
	${PACKAGE} ${DIR}/PRISM-${L}-v${VERSION}.7z ${F2}
	cd ${DIR};${PACKAGE} PRISM-${L}-v${VERSION}.7z PRISM-${L}
	cp ${DIR}/PRISM-${L} ${BIN}linux/

package-prism-darwin:
	${PACKAGE} ${DIR}/PRISM-${D}-v${VERSION}.7z ${F2}
	cd ${DIR};${PACKAGE} PRISM-${D}-v${VERSION}.7z PRISM-${D}
	cp ${DIR}/PRISM-${D} ${BIN}darwin/

package-all: package-agent-windows package-agent-dll package-agent-linux package-agent-darwin package-prism-windows package-server-windows package-server-linux package-server-darwin

clean:
	rm -rf ${DIR}*

#Build all files for release distribution
distro: clean all package-all
