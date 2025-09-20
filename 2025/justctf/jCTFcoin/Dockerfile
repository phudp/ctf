FROM ubuntu:24.04@sha256:1e622c5f073b4f6bfad6632f2616c7f59ef256e96fe78bf6a595d1dc4376ac02 AS base
FROM pwn.red/jail

COPY --from=base / /srv

ENV user=root
ENV port=5000

COPY flag.txt /srv/app/flag.txt
COPY jctfcoin /srv/app/run
COPY blockchain.so /srv/app/blockchain.so

ENV JAIL_CONNS_PER_IP=3
ENV JAIL_TIME=600
ENV JAIL_PIDS=10
