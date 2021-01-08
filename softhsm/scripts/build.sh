#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

docker rm credentials-support-test --force

cd $SCRIPT_DIR/..
mvn clean install dockerfile:build


