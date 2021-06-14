#!/bin/sh
. ./config.sh

mkdir -p obj-intel64
make PIN_ROOT=$PIN_ROOT obj-intel64/tool.so
