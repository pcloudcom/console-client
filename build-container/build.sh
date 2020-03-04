#!/bin/bash -e

BUILD_DIR=/work

cd $BUILD_DIR/pCloudCC/lib/pclsync/ && make clean && make fs

cd $BUILD_DIR/pCloudCC/lib/mbedtls/ && cmake . && make clean && make

cd $BUILD_DIR/pCloudCC/ && cmake . && make
