FROM alpine:latest

RUN apk add --no-cache \
    clang \
    musl-dev \
    linux-headers \
    make \
    cmocka-dev

WORKDIR /app
COPY . .
RUN make test-build

CMD ["./tests/test_discovery"]
