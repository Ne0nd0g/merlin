# Image source is located at https://github.com/Ne0nd0g/merlin-docker/blob/main/Dockerfile
# Image repository is at https://hub.docker.com/r/ne0nd0g/merlin-base
FROM ne0nd0g/merlin-base:v1.5.0

# Build the Docker image first
#  > sudo docker build -t merlin-server .

# To start the Merlin Server and interact with it, run:
#  > sudo docker run -p 50051:50051 -p 443:443 -v ~/merlin:/opt/merlin/data merlin-server:latest

# Port 50051 is the gRPC port for the Merlin CLI to connect to
# Port 443 is the port where a Merlin listener will bind to
# Run the docker image with extra '-p' arguments to expose more ports for Merlin listeners to bind to

WORKDIR /opt/merlin

ENTRYPOINT ["./merlinServer-Linux-x64", "-addr", "0.0.0.0:50051"]
