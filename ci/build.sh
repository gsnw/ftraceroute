#!/bin/bash
set -x

PATH=$(pwd)/ci/build/bin:$PATH

if [ ! -d ci ]; then
    echo "you must run this in the root fping directory" >&2
    exit 1
fi

autoreconf --install
./configure --prefix=/opt/ftraceroute
make CFLAGS="-g -O0 -fprofile-arcs -ftest-coverage"

sudo chown root src/ftraceroute
sudo chmod u+s  src/ftraceroute