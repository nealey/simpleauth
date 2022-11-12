#! /bin/sh

set -e

tag=git.woozle.org/neale/wallart-server

cd $(dirname $0)/..
docker build -t $tag -f build/Dockerfile .
docker push $tag
