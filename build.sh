#! /bin/sh

set -e

tag=git.woozle.org/neale/simpleauth:latest

docker buildx --push --tag $tag $(dirname $0)/.
