FROM docker.sunet.se/openjdk-jre-luna:luna7.4-jre17
#FROM docker.sunet.se/openjdk-jre-luna:luna7.4-jre11

# Make softhsm2 available for install
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN apt-get -q update
RUN apt-get -y upgrade
# Install softhsm2
RUN apt-get install -y procps softhsm2
# Install pkcs11-tool
RUN apt-get -y install opensc

# Setup softhsm
RUN rm -rf /var/lib/softhsm/tokens && mkdir /var/lib/softhsm/tokens


RUN mkdir /opt/credentials-test

# Setup the tokens (for SoftHSM it involves writing keys and certs)
#
COPY scripts/setup-tokens.sh /opt/credentials-test
COPY src/main/resources/credentials /opt/credentials-test/credentials
RUN chmod a+x /opt/credentials-test/setup-tokens.sh && bash /opt/credentials-test/setup-tokens.sh

# Copy the PKCS#11 configuration files. Normally we would use a volume and not copy the files
#
COPY src/main/resources/conf*.cfg /opt/credentials-test/

# Copy Spring Boot jar and setup Java
#
ADD target/credentials-support-test.jar /opt/credentials-test/credentials-support-test.jar

ENV JAVA_OPTS="-Djava.security.egd=file:/cfg/./urandom -Dtest.pkcs11.enabled=true"
  
ENTRYPOINT exec java $JAVA_OPTS -jar /opt/credentials-test/credentials-support-test.jar

EXPOSE 8080 8443
