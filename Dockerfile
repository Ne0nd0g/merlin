FROM golang:1.16-buster

# Build the Docker image first
#  > sudo docker build -t merlin .

# To start the Merlin Server, run
#  > sudo docker run -it -p 443:443 -v ~/merlin-server-log:/opt/merlin/data/log -v ~/merlin-agent-logs:/opt/merlin/data/agents merlin:latest

# Update APT
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y apt-transport-https vim gcc-mingw-w64 unzip

# Install Microsoft package signing key
RUN wget --quiet -O - https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg
RUN mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/
RUN wget --quiet https://packages.microsoft.com/config/debian/10/prod.list
RUN mv prod.list /etc/apt/sources.list.d/microsoft-prod.list
RUN chown root:root /etc/apt/trusted.gpg.d/microsoft.asc.gpg
RUN chown root:root /etc/apt/sources.list.d/microsoft-prod.list

# Install Microsoft .NET Core 2.1 SDK
RUN apt-get update
RUN apt-get install -y dotnet-sdk-2.1

# Clone Merlin Server
WORKDIR /opt
RUN git clone --recurse-submodules https://github.com/Ne0nd0g/merlin
WORKDIR /opt/merlin
RUN go mod download

# Clone Merlin Agent
WORKDIR /opt/
RUN git clone https://github.com/Ne0nd0g/merlin-agent
WORKDIR /opt/merlin-agent
RUN go mod download
RUN make all

# Clone Merlin Agent DLL
WORKDIR /opt/
RUN git clone https://github.com/Ne0nd0g/merlin-agent-dll
WORKDIR /opt/merlin-agent-dll
RUN go mod download
RUN make

# Build SharpGen
WORKDIR /opt/merlin/data/src/cobbr/SharpGen
RUN dotnet build -c release

# Download Mimikatz
WORKDIR /opt/merlin/data/src/
RUN wget https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip
RUN unzip mimikatz_trunk.zip -d mimikatz
RUN rm /opt/merlin/data/src/mimikatz_trunk.zip

# Port that the agent will communicate with the server on
EXPOSE 443

WORKDIR /opt/merlin
CMD ["go", "run", "main.go"]
