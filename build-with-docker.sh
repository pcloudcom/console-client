#!/bin/bash -e

PROJECT_DIR=$(cd `dirname $0` && pwd)

cd $PROJECT_DIR/build-container

docker build --tag pcloudcc-build:local .

cd $PROJECT_DIR
docker run \
	-u $(id -u):$(id -g) \
	-v $PROJECT_DIR:/work \
	pcloudcc-build:local \
	/build/build.sh
