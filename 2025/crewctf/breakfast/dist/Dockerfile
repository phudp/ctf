# Sample Dockerfile for building the binary.
# docker build -t breakfast .
# docker run -it -v ./build:/home/user/build breakfast /bin/bash
# 
# Install debug tools or extract the binary (`cp breakfast build`) as you like.
# 
FROM ubuntu:24.04

RUN apt-get update && apt-get -y install build-essential

WORKDIR /home/user/
COPY breakfast.cpp /home/user/
COPY cereal-1.3.2/ /home/user/cereal/

RUN g++ -I cereal/include/ -o breakfast breakfast.cpp
RUN ["/bin/bash"]
