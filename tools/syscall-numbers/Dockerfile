FROM debian:bookworm

RUN apt-get update && apt-get install -y gcc
RUN useradd -m builder

COPY --chown=builder . /home/builder

USER builder
WORKDIR /home/builder

RUN sh generate-print-statements.sh
RUN gcc main.c -o main
CMD ./main
