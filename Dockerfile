FROM golang:stretch

# Build the Docker image first
#  > sudo docker build -t merlin .

# To start the Merlin Server, run
#  > sudo docker run -it -p 443:443 -v merlinAgents:/go/src/github.com/Ne0nd0g/merlin/data/agents -v merlinLog:/go/src/github.com/Ne0nd0g/merlin/data/log -v merlinTemp:/go/src/github.com/Ne0nd0g/merlin/data/temp merlin:latest

# Update APT
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y apt-transport-https

# Install Microsoft package signing key
RUN wget --quiet -O - https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg
RUN mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/
RUN wget --quiet https://packages.microsoft.com/config/debian/9/prod.list
RUN mv prod.list /etc/apt/sources.list.d/microsoft-prod.list
RUN chown root:root /etc/apt/trusted.gpg.d/microsoft.asc.gpg
RUN chown root:root /etc/apt/sources.list.d/microsoft-prod.list

# Install Microsoft .NET Core 2.1 SDK
RUN apt-get update
RUN apt-get install -y dotnet-sdk-2.1

RUN apt-get install -y git make vim gcc-mingw-w64

# Clone Merlin
WORKDIR $GOPATH/src/github.com/Ne0nd0g
RUN git clone --recurse-submodules https://github.com/Ne0nd0g/merlin

# Build SharpGen
WORKDIR $GOPATH/src/github.com/Ne0nd0g/merlin/data/src/cobbr/SharpGen
RUN dotnet build -c release

WORKDIR $GOPATH/src/github.com/Ne0nd0g/merlin
RUN go mod download
RUN make generate-agents

# > sudo docker volume inspect merlinAgents to find data location on host OS
#VOLUME ["merlinAgents:data/agents", "merlinLog:data/log", "merlinTemp:data/temp"]
EXPOSE 443

CMD ["go", "run", "cmd/merlinserver/main.go"]
