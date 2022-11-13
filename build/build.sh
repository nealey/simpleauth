#! /bin/sh

set -e

tag=git.woozle.org/neale/simpleauth

cd $(dirname $0)/..
docker build -t $tag -f build/Dockerfile .
docker push $tag
