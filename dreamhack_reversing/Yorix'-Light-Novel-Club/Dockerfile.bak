# hey you don't need exact image version, trust me
FROM ubuntu:24.04

COPY ./build/club_server /app/build/club_server
COPY ./books /app/books
COPY ./keys /app/keys
COPY ./run.sh /app/run.sh

WORKDIR /app

EXPOSE 4444

CMD ["./run.sh"]