FROM node:20-alpine AS builder

RUN apk add --no-cache python3 make g++

WORKDIR /src

COPY binding.gyp binding.gyp
COPY native/ native/

RUN npx node-gyp rebuild --release

FROM scratch AS artifact
COPY --from=builder /src/build/Release/syscall.node /syscall.node
