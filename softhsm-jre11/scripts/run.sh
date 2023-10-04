#!/bin/bash

docker run -d --name credentials-support-test-jre11 \
  -p 8080:8080 \
  -e SPRING_PROFILES_ACTIVE=softhsm \
  credentials-support-test-jre11

docker logs -f credentials-support-test-jre11
