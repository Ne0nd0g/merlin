# Merlin version
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
BUILD=$(shell git rev-parse HEAD)

# Output File Location
DIR=data/temp/v${VERSION}/${BUILD}
$(shell mkdir -p ${DIR})

# Go build flags
LDFLAGS=-ldflags '-X github.com/Ne0nd0g/merlin/v2/pkg.Build=${BUILD} -X github.com/Ne0nd0g/merlin/v2/pkg.Version=${VERSION} -buildid='

# Build fully static, pure-Go binaries for every target. The server uses no cgo,
# so this only forces static linking + Go's native net/user resolvers and makes
# builds deterministic regardless of which C toolchains exist on the build host.
export CGO_ENABLED := 0

# Misc
# The Merlin server and agent MUST be built with the same seed value
# Set during build with "make linux-garble SEED=<insert seed>
SEED=d0d03a0ae4722535a0e1d5d0c8385ce42015511e68d960fadef4b4eaf5942feb

default:
	go build ${LDFLAGS} -o ${DIR}/${MSERVER} main.go

# Compile Server - Windows x64
windows:
	export GOOS=windows && export GOARCH=amd64 && go build ${LDFLAGS} -o ${DIR}/merlinServer-Windows-x64.exe main.go

# The SEED must be the exact same that was used when compiling the agent
# Garble version 0.5.2 or later must be installed and accessible in the PATH environment variable
windows-garble:
	export GOOS=windows GOARCH=amd64 &&garble -tiny -literals -seed ${SEED} build ${LDFLAGS} -o ${DIR}/merlinServer-Windows-x64.exe main.go

# Compile Server - Linux x64
linux:
	export GOOS=linux && export GOARCH=amd64 && go build ${LDFLAGS} -o ${DIR}/merlinServer-Linux-x64 main.go

# Compile Server - Linux arm (armv7)
linux-arm:
	export GOOS=linux && export GOARCH=arm && export GOARM=7 && go build ${LDFLAGS} -o ${DIR}/merlinServer-Linux-arm main.go

# Compile Server - Linux arm64
linux-arm64:
	export GOOS=linux && export GOARCH=arm64 && go build ${LDFLAGS} -o ${DIR}/merlinServer-Linux-arm64 main.go

# The SEED must be the exact same that was used when compiling the agent
# Garble version 0.5.2 or later must be installed and accessible in the PATH environment variable
linux-garble:
	export GOOS=linux GOARCH=amd64 && garble -tiny -literals -seed ${SEED} build ${LDFLAGS} -o ${DIR}/merlinServer-Linux-x64 main.go

# Compile Server - Darwin x64
darwin:
	export GOOS=darwin && export GOARCH=amd64 && go build ${LDFLAGS} -o ${DIR}/merlinServer-Darwin-x64 main.go

# Compile Server - Darwin arm64 (Apple Silicon)
darwin-arm64:
	export GOOS=darwin && export GOARCH=arm64 && go build ${LDFLAGS} -o ${DIR}/merlinServer-Darwin-arm64 main.go

# The SEED must be the exact same that was used when compiling the agent
# Garble version 0.5.2 or later must be installed and accessible in the PATH environment variable
darwin-garble:
	export GOOS=darwin GOARCH=amd64 && garble -tiny -literals -seed ${SEED} build ${LDFLAGS} -o ${DIR}/merlinServer-Darwin-x64.exe main.go

distro: windows linux linux-arm linux-arm64 darwin darwin-arm64

clean:
	rm -rf ${DIR}*
