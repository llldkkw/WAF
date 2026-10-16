# syntax=docker/dockerfile:1
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /waf ./cmd/waf

FROM gcr.io/distroless/static-debian12
COPY --from=build /waf /usr/local/bin/waf
ENV WAF_CONFIG=/etc/waf/waf.yaml
VOLUME ["/var/lib/waf"]
EXPOSE 80 443
ENTRYPOINT ["/usr/local/bin/waf"]
CMD ["serve"]
