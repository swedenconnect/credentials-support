FROM docker.sunet.se/openjdk-jre-luna:luna7.4-jre11

# Install pkcs11-tool
#
RUN apt-get update && apt-get install -y pcscd libccid libpcsclite-dev libssl-dev libreadline-dev autoconf automake build-essential docbook-xsl xsltproc libtool pkg-config && \
    wget https://github.com/OpenSC/OpenSC/releases/download/0.19.0/opensc-0.19.0.tar.gz && \
    tar xfvz opensc-*.tar.gz && \
    cd opensc-0.19.0 && \
    ./bootstrap && ./configure --prefix=/usr --sysconfdir=/etc/opensc && \
    make && make install && \
    cd .. && rm -rf opensc*

# Setup softhsm
RUN rm -rf /var/lib/softhsm/tokens && mkdir /var/lib/softhsm/tokens


RUN mkdir /opt/credentials-test

# Setup the tokens (for SoftHSM it involves writing keys and certs)
#
COPY scripts/setup-tokens.sh /opt/credentials-test
COPY src/main/resources/credentials /opt/credentials-test/credentials
RUN chmod a+x /opt/credentials-test/setup-tokens.sh && /opt/credentials-test/setup-tokens.sh 

# Copy the PKCS#11 configuration files. Normally we would use a volume and not copy the files
#
COPY src/main/resources/conf*.cfg /opt/credentials-test/

# Copy Spring Boot jar and setup Java
#
ADD target/credentials-support-test.jar /opt/credentials-test/credentials-support-test.jar

ENV JAVA_OPTS="-Djava.security.egd=file:/cfg/./urandom -Dtest.pkcs11.enabled=true"
  
ENTRYPOINT exec java $JAVA_OPTS -jar /opt/credentials-test/credentials-support-test.jar

EXPOSE 8080 8443
