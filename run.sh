#!/bin/sh
. ./config.sh

mkdir -p $OUTPUT_DIR 
$PIN_ROOT/pin -t obj-intel64/tool.so -o $OUTPUT_DIR -- $1 $2 $3 $4 $5
