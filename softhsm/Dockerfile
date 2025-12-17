FROM docker.sunet.se/openjdk-jre-luna:luna7.4-jre17

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies (allow Debian "stable" release info changes)
RUN apt-get -q update --allow-releaseinfo-change \
 && apt-get -y upgrade \
 && apt-get -y install --no-install-recommends procps softhsm2 opensc \
 && rm -rf /var/lib/apt/lists/*

# Setup softhsm
RUN rm -rf /var/lib/softhsm/tokens \
 && mkdir -p /var/lib/softhsm/tokens

RUN mkdir -p /opt/credentials-test

# Setup the tokens (for SoftHSM it involves writing keys and certs)
COPY scripts/setup-tokens.sh /opt/credentials-test/setup-tokens.sh
COPY src/main/resources/credentials /opt/credentials-test/credentials
RUN chmod a+x /opt/credentials-test/setup-tokens.sh \
 && bash /opt/credentials-test/setup-tokens.sh

# Copy the PKCS#11 configuration files. Normally we would use a volume and not copy the files
COPY src/main/resources/conf*.cfg /opt/credentials-test/

# Copy Spring Boot jar and setup Java
ADD target/credentials-support-test.jar /opt/credentials-test/credentials-support-test.jar

ENV JAVA_OPTS="-Djava.security.egd=file:/cfg/./urandom"

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /opt/credentials-test/credentials-support-test.jar"]

EXPOSE 8080 8443
