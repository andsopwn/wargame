FROM ubuntu:24.04

# 런타임 의존성
RUN apt-get update && \
    apt-get install -y --no-install-recommends libssl3 libstdc++6 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 로컬의 최상단에 있는 바이너리만 복사
COPY ./club_server /app/club_server

# 서버가 참조할 수도 있는 경로 미리 준비(비어 있어도 OK)
RUN mkdir -p /app/books /app/keys

# 실행권한
RUN chmod +x /app/club_server

EXPOSE 4444
CMD ["/app/club_server"]
