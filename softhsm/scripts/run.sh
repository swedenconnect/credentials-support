#!/bin/bash

docker run -d --name credentials-support-test \
  -p 8080:8080 \
  -e SPRING_PROFILES_ACTIVE=softhsm \
  credentials-support-test

docker logs -f credentials-support-test
