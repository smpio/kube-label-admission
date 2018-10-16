FROM golang:1.10 as builder

WORKDIR /go/src/github.com/smpio/kube-label-admission/

RUN curl https://glide.sh/get | sh

COPY glide.yaml glide.lock ./
RUN glide install

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags "-s -w"


FROM scratch
COPY --from=builder /go/src/github.com/smpio/kube-label-admission/kube-label-admission /
ENTRYPOINT ["/kube-label-admission"]
