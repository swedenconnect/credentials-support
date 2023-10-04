#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

docker rm credentials-support-test-jre11 --force

pushd $SCRIPT_DIR/..

mvn clean install
docker build -t credentials-support-test-jre11:latest --platform linux/arm64 .



