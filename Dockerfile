FROM ne0nd0g/merlin-base

# Build the Docker image first
#  > sudo docker build -t merlin .

# To start the Merlin Server and interact with it, run:
#  > sudo docker run -it -p 443:443 -v ~/merlin:/opt/merlin/data merlin:latest

WORKDIR /opt/merlin

ENTRYPOINT ["go", "run", "main.go"]
