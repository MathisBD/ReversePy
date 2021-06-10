#!/bin/sh
. ./config.sh

make PIN_ROOT=$PIN_ROOT obj-intel64/inscount.so
