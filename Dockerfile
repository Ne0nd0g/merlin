FROM golang:stretch
MAINTAINER @audibleblink

# To just generate binaries, run the following and check your `src` folder for the output:
#  > sudo docker build -t merlin .
#  > sudo docker run --rm --mount type=bind,src=/tmp,dst=/go/src/github.com/Ne0nd0g/merlin/data/temp merlin make linux
# > ls /tmp/v0.6.4.BETA

# To run the server, run
#  > sudo docker run -it -p 443:443 merlin


RUN apt-get update && apt-get install -y git make
RUN go get github.com/Ne0nd0g/merlin/...

WORKDIR $GOPATH/src/github.com/Ne0nd0g/merlin
VOLUME ["data/temp"]
EXPOSE 443
CMD ["go", "run", "cmd/merlinserver/main.go", "-i", "0.0.0.0"]
