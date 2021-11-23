FROM ubuntu

ENV GOPATH=/usr/local/go

RUN apt-get update && \
    apt-get install -y clang make wget iproute2 linux-libc-dev libc6-dev-i386 libc6-dev linux-headers-$(uname -r)

RUN wget https://golang.org/dl/go1.17.3.linux-amd64.tar.gz \
    && tar -zxvf go1.17.3.linux-amd64.tar.gz -C /usr/local/

COPY . .

RUN make filter

CMD ["./docker_entrypoint.sh"]
