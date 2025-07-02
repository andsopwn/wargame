FROM ubuntu:24.04

USER root
RUN apt-get update && apt-get install -y socat

WORKDIR /

RUN mkdir /jail

COPY chrootsquare .
COPY flag.txt .

RUN chmod 0755 /chrootsquare
RUN chmod 0755 /flag.txt

EXPOSE 5000

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:/chrootsquare,nofork,stderr"]