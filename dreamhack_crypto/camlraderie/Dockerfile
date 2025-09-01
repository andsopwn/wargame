FROM alpine:3.21@sha256:56fa17d2a7e7f168a043a2712e63aed1f8543aeafdcee47c58dcffe38ed51099

ENV USER chall

USER root
RUN apk add socat opam gcc libc-dev make
RUN adduser -D -g "" -u 1337 $USER

USER $USER
WORKDIR /app
COPY ./deploy/main.ml /app
COPY ./deploy/flag /app

RUN opam init --disable-sandboxing --compiler=5.2.1

EXPOSE 5000

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:/home/chall/.opam/5.2.1/bin/ocaml main.ml,nofork,stderr"]