
`docker run --name pkcs11 --rm -i -t docker.sunet.se/openjdk-jre-luna:luna6.2-jre11 bash`

Build docker image:

`docker build -t pkcs11-image .`

Execute bash in the container:

`docker run --name pkcs11 --rm -i -t pkcs11-image bash`
