FROM rust:latest
MAINTAINER Sebastien Tricaud <sebastien@honeynet.org>
RUN apt update -q
RUN apt -qy --no-install-recommends install git apt-transport-https ca-certificates pkg-config openssl libssl-dev jed
RUN update-ca-certificates
WORKDIR /opt/
RUN git clone https://github.com/stricaud/sightingdb.git /opt/sightingdb
WORKDIR /opt/sightingdb
RUN cargo build --release
COPY sightingdb.conf /etc/sightingdb/
RUN mkdir /etc/sightingdb/ssl
WORKDIR /etc/sightingdb/ssl
COPY ssl-answers /etc/sightingdb/ssl/
RUN openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout key.pem -out cert.pem < /etc/sightingdb/ssl/ssl-answers
WORKDIR /opt/sightingdb/
RUN mkdir /var/log/sightingdb/

EXPOSE 9999
COPY sightingdb-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/sightingdb-entrypoint.sh"]

