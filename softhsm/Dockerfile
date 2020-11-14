FROM docker.sunet.se/openjdk-jre-luna:luna6.2-jre11

# Install pkcs11-tool
RUN apt-get update && apt-get install -y pcscd libccid libpcsclite-dev libssl-dev libreadline-dev autoconf automake build-essential docbook-xsl xsltproc libtool pkg-config && \
    wget https://github.com/OpenSC/OpenSC/releases/download/0.19.0/opensc-0.19.0.tar.gz && \
    tar xfvz opensc-*.tar.gz && \
    cd opensc-0.19.0 && \
    ./bootstrap && ./configure --prefix=/usr --sysconfdir=/etc/opensc && \
    make && make install && \
    cd .. && rm -rf opensc*

# Setup softhsm
RUN rm -rf /var/lib/softhsm/tokens && mkdir /var/lib/softhsm/tokens

#ADD target/se-proxy-service-1.3.5-SNAPSHOT.jar /app.jar
#COPY src/main/resources/cfg/start.sh /

#ENTRYPOINT /start.sh

#EXPOSE 8080
#EXPOSE 8443
#EXPOSE 8009
#EXPOSE 8008
