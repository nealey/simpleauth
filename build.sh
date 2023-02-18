#! /bin/sh

set -e

tag=git.woozle.org/neale/simpleauth:latest

docker buildx build --push --tag $tag $(dirname $0)/.
