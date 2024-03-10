FROM ubuntu@sha256:27cb6e6ccef575a4698b66f5de06c7ecd61589132d5a91d098f7f3f9285415a9

RUN apt update
RUN apt-get install -y socat

COPY ./deploy/flag /flag
COPY ./deploy/kind_kid_list /kind_kid_list

RUN chmod 755 /flag /kind_kid_list

EXPOSE 7182
CMD socat TCP-LISTEM:7182, reuseaddr, fork EXEC:/kind_kid_list
