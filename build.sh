#!/bin/sh
. ./config.sh

mkdir -p obj-intel64/src 
make PIN_ROOT=$PIN_ROOT obj-intel64/src/tool.so
