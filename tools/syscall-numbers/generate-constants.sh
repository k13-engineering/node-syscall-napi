#!/bin/sh

set -e

generateConstants() {

    platform=$1
    constantsFile=$2

    docker build --platform=${platform} -f Dockerfile -t tmp .
    docker run --rm tmp > ${constantsFile}
}

# change to the script directory
cd "$(dirname "$0")"

generateConstants linux/amd64 ../../lib/constants/x64.js
generateConstants linux/arm64 ../../lib/constants/arm64.js
generateConstants linux/arm ../../lib/constants/arm.js
